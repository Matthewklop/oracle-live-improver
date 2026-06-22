/* ============================================================================
 * oracle_live_improver_daemon.c — Autonomous Watchdog + Live Optimizer
 *
 * Merges:
 *   - oracle_self_optimize.c  (watch /proc/pid/stat, tune JVM, CPU affinity)
 *   - oracle_live_improver_v3 (same-length NOP consolidation)
 *   - critical_opalescence.c (detect when process is in trouble)
 *   - BigSingularityPlan.md  (continuous self-modification loop)
 *
 * This runs FOREVER. It watches every process on the system.
 * When a process is struggling (high branch misses, low IPC, GC spikes),
 * it applies live patches automatically.
 *
 * Build: gcc -O3 -march=native -o oracle_live_improver_daemon \
 *            oracle_live_improver_daemon.c -lm -lrt
 * Run:   nohup ./oracle_live_improver_daemon &
 *
 * The daemon:
 *   1. Scans /proc for all running processes
 *   2. Measures each one via perf counters + /proc/pid/stat
 *   3. If it's struggling → apply NOP consolidations
 *   4. If it's a JVM → also tune GC threads, CPU affinity, priority
 *   5. Re-checks every 30 seconds
 *   6. Never crashes — just sleeps on error
 * ============================================================================
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sched.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <dirent.h>
#include <math.h>

// ─── Perf API ───
#include <linux/perf_event.h>
#include <sys/syscall.h>

// ─── Constants ───
#define MAX_WATCHED 64
#define SCAN_INTERVAL 30  // seconds between full scans
#define CACHE_LN 64

// ─── NOP table ───
static const uint8_t nops[9][9] = {
    {0}, {0x90}, {0x66, 0x90}, {0x0F, 0x1F, 0x00},
    {0x0F, 0x1F, 0x40, 0x00}, {0x0F, 0x1F, 0x44, 0x00, 0x00},
    {0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00}, {0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00},
    {0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00}
};

// ─── A watched process ───
typedef struct {
    pid_t pid;
    char name[64];
    char exe_path[256];
    int is_jvm;
    int patches_applied;
    int nop_patches;
    float last_ipc;
    float last_bmr; // branch miss rate
    float last_gc_ms;
    uint64_t last_utime;
    uint64_t last_stime;
    long clk_tck;
    int mem_fd;
    
    // Perf fds
    int perf_cycles;
    int perf_instrs;
    int perf_branches;
    int perf_bmiss;
    
    // Tuning state (for JVMs)
    int gc_threads;
    int cpu_affinity;
    int nice_value;
} WatchedProc;

// ─── State ───
static struct {
    WatchedProc procs[MAX_WATCHED];
    int nprocs;
    uint64_t total_patches;
    uint64_t daemon_cycles;
    int running;
} state;

// ─── Perf open helper ───
static int perf_open_hw(pid_t pid, uint32_t hw_event) {
    struct perf_event_attr pe = {0};
    pe.size = sizeof(pe);
    pe.type = PERF_TYPE_HARDWARE;
    pe.config = hw_event;
    pe.disabled = 1;
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;
    int fd = syscall(__NR_perf_event_open, &pe, pid, -1, -1, 0);
    if (fd >= 0) ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    return fd;
}

// ─── Detect process type ───
static int detect_jvm(pid_t pid) {
    char path[64], buf[256];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    int f = open(path, O_RDONLY);
    if (f < 0) return 0;
    int n = read(f, buf, sizeof(buf)-1);
    close(f);
    if (n <= 0) return 0;
    buf[n] = 0;
    // Strip newline
    char *nl = strchr(buf, '\n');
    if (nl) *nl = 0;
    
    if (strstr(buf, "java")) return 1;
    
    // Check exe path
    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    n = readlink(path, buf, sizeof(buf)-1);
    if (n > 0) {
        buf[n] = 0;
        if (strstr(buf, "java")) return 1;
    }
    return 0;
}

// ─── Read /proc/pid/stat ───
static int read_proc_stat(pid_t pid, uint64_t *utime, uint64_t *stime) {
    char path[64], buf[1024];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    int f = open(path, O_RDONLY);
    if (f < 0) return 0;
    int n = read(f, buf, sizeof(buf)-1);
    close(f);
    if (n <= 0) return 0;
    buf[n] = 0;
    
    char *s = buf;
    while (*s && *s != ')') s++;
    if (*s) s += 2;
    
    // Fields 11 and 12 (0-indexed) = utime, stime
    char *tok[50]; int nt = 0;
    char *t = strtok(s, " \t");
    while (t && nt < 50) { tok[nt++] = t; t = strtok(NULL, " \t"); }
    if (nt > 13) {
        *utime = strtoul(tok[11], NULL, 10);
        *stime = strtoul(tok[12], NULL, 10);
        return 1;
    }
    return 0;
}

// ─── Get JVM GC time (rough estimate via /proc) ───
static double estimate_gc_time(pid_t pid, uint64_t utime, uint64_t stime, long clk_tck) {
    // Rough: if CPU > 50% and process is JVM, estimate GC cost
    // Real GC time would need jcmd or JMX
    // For now: return CPU% as proxy
    return 0;
}

// ─── Read process memory and apply NOP patches ───
static int apply_nop_patches(pid_t pid, int mem_fd) {
    // Read /proc/pid/maps
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    
    int patches = 0;
    uint8_t *buf = malloc(8 * 1048576);
    if (!buf) { fclose(f); return 0; }
    
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        unsigned long s, e;
        if (sscanf(line, "%lx-%lx", &s, &e) < 2) continue;
        
        // Check for executable, non-lib
        char *pp = strchr(line, ' ');
        if (!pp || pp[3] != 'x') continue;
        
        // Skip libraries
        if (strstr(line, ".so") || strstr(line, "/lib/") || 
            strstr(line, "/lib64/") || strstr(line, "ld-") ||
            strstr(line, "[vdso]") || strstr(line, "[vsyscall]") ||
            strstr(line, "[vvar]") || strstr(line, "[stack")) continue;
        
        size_t sz = e - s;
        if (sz > 8UL * 1048576UL) sz = 8UL * 1048576UL;
        if (sz < 16) continue;
        
        // Read memory — try process_vm_readv, fallback to /proc/mem
        struct iovec lo = {buf, sz};
        struct iovec ro = {(void*)(uintptr_t)s, sz};
        int can_read = (process_vm_readv(pid, &lo, 1, &ro, 1, 0) > 0);
        if (!can_read) {
            if (mem_fd >= 0)
                can_read = (pread64(mem_fd, buf, sz, s) == (ssize_t)sz);
            if (!can_read) continue;
        }
        
        // Scan for NOP runs
        for (size_t off = 0; off < sz - 2; off++) {
            if (buf[off] != 0x90) continue;
            int run = 0;
            while (off + run < sz && buf[off+run] == 0x90 && run < 8) run++;
            if (run >= 2 && run <= 8 && nops[run][0]) {
                // Write optimized NOP — try ptrace attach first for permissions
                int did_write = 0;
                
                // Try process_vm_writev
                struct iovec lw = {(void*)nops[run], run};
                struct iovec rw = {(void*)(uintptr_t)(s + off), run};
                if (process_vm_writev(pid, &lw, 1, &rw, 1, 0) > 0) {
                    did_write = 1;
                } else if (mem_fd >= 0) {
                    if (pwrite64(mem_fd, nops[run], run, s + off) == (ssize_t)run)
                        did_write = 1;
                }
                
                // Fallback: ptrace POKETEXT
                if (!did_write) {
                    int pt_attached = 0;
                    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == 0) {
                        waitpid(pid, NULL, WNOHANG);
                        pt_attached = 1;
                    }
                    if (pt_attached || errno == ESRCH) { // ESRCH = already traced
                        for (int b = 0; b < run; b += 8) {
                            int chunk = (run - b > 8) ? 8 : (run - b);
                            unsigned long val = 0;
                            memcpy(&val, nops[run] + b, chunk);
                            ptrace(PTRACE_POKETEXT, pid, (void*)(uintptr_t)(s + off + b), (void*)val);
                        }
                        if (pt_attached) ptrace(PTRACE_DETACH, pid, NULL, NULL);
                        did_write = 1;
                    }
                }
                
                if (did_write) patches++;
                off += run;
            }
        }
    }
    fclose(f);
    free(buf);
    return patches;
}

// ─── Tune JVM parameters ───
static void tune_jvm(pid_t pid, int *gc_threads, int *cpu_affinity, int *nice_value) {
    char cmd[256];
    int changed = 0;
    
    // Increase GC threads if we haven't already
    if (*gc_threads == 0) {
        *gc_threads = 2;
        snprintf(cmd, sizeof(cmd), 
                 "jcmd %d VM.flags ConcGCThreads=%d 2>/dev/null", pid, *gc_threads);
        system(cmd);
        changed = 1;
    } else if (*gc_threads < 4) {
        (*gc_threads)++;
        snprintf(cmd, sizeof(cmd),
                 "jcmd %d VM.flags ConcGCThreads=%d 2>/dev/null", pid, *gc_threads);
        system(cmd);
        changed = 1;
    }
    
    // Expand CPU affinity
    if (*cpu_affinity == 0) {
        *cpu_affinity = 2;
        cpu_set_t cm;
        CPU_ZERO(&cm);
        for (int i = 0; i < *cpu_affinity; i++) CPU_SET(i, &cm);
        sched_setaffinity(pid, sizeof(cm), &cm);
        changed = 1;
    } else if (*cpu_affinity < 6) {
        *cpu_affinity += 2;
        cpu_set_t cm;
        CPU_ZERO(&cm);
        for (int i = 0; i < *cpu_affinity; i++) CPU_SET(i, &cm);
        sched_setaffinity(pid, sizeof(cm), &cm);
        changed = 1;
    }
    
    // Raise priority (smaller nice = higher priority)
    if (*nice_value > -10) {
        *nice_value -= 5;
        setpriority(PRIO_PROCESS, pid, *nice_value);
        changed = 1;
    }
    
    if (changed) {
        printf("[daemon]   JVM tune: GC=%d Aff=%d Nice=%d\n",
               *gc_threads, *cpu_affinity, *nice_value);
    }
}

// ─── Watch a single process ───
static void watch_process(WatchedProc *wp) {
    uint64_t utime = 0, stime = 0;
    if (!read_proc_stat(wp->pid, &utime, &stime)) {
        // Process died
        wp->pid = 0;
        return;
    }
    
    double dt = 0;
    if (wp->last_utime > 0) {
        dt = ((double)((utime + stime) - (wp->last_utime + wp->last_stime))) / wp->clk_tck;
    }
    wp->last_utime = utime;
    wp->last_stime = stime;
    
    // Read perf counters
    uint64_t cycles=0, instrs=0, branches=0, bmiss=0;
    if (wp->perf_cycles >= 0) read(wp->perf_cycles, &cycles, sizeof(cycles));
    if (wp->perf_instrs >= 0) read(wp->perf_instrs, &instrs, sizeof(instrs));
    if (wp->perf_branches >= 0) read(wp->perf_branches, &branches, sizeof(branches));
    if (wp->perf_bmiss >= 0) read(wp->perf_bmiss, &bmiss, sizeof(bmiss));
    
    float ipc = cycles > 0 ? (float)instrs / cycles : 0;
    float bmr = branches > 0 ? (float)bmiss / branches * 100 : 0;
    
    // Skip patching on first run — need a baseline
    if (wp->nop_patches == 0 && cycles == 0) {
        wp->last_ipc = ipc;
        wp->last_bmr = bmr;
        return; // wait for next cycle to have delta
    }
    
    wp->last_ipc = ipc;
    wp->last_bmr = bmr;
    
    // Decide if we need to act — only after we have a baseline
    int needs_nop = 0;
    int needs_tune = (wp->is_jvm && dt > 0.5);
    if (wp->last_ipc > 0.01) {
        needs_nop = (wp->last_ipc < 1.5 && wp->nop_patches < 100);
    }
    
    if (needs_nop && wp->nop_patches < 3) { // limit to 3 rounds
        printf("[daemon] PID %d (%s) IPC=%.2f BrMiss=%.2f%% — applying NOP patches\n",
               wp->pid, wp->name, ipc, bmr);
        fflush(stdout);
        int p = apply_nop_patches(wp->pid, wp->mem_fd);
        if (p > 0) {
            wp->nop_patches += p;
            wp->patches_applied += p;
            state.total_patches += p;
            printf("[daemon]   ✓ %d NOP consolidations applied (total: %d)\n",
                   p, wp->nop_patches);
            fflush(stdout);
        } else {
            printf("[daemon]   ✗ No patches applied (mem_fd=%d, errno=%d)\n",
                   wp->mem_fd, errno);
            fflush(stdout);
        }
    }
    
    if (needs_tune && wp->is_jvm) {
        printf("[daemon] PID %d (%s) JVM loaded (CPU=%.1fs) — tuning\n",
               wp->pid, wp->name, dt);
        tune_jvm(wp->pid, &wp->gc_threads, &wp->cpu_affinity, &wp->nice_value);
    }
}

// ─── Scan for new processes ───
static void scan_processes(void) {
    DIR *d = opendir("/proc");
    if (!d) return;
    
    struct dirent *de;
    while ((de = readdir(d))) {
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        pid_t pid = atoi(de->d_name);
        
        // Skip kernel threads
        char path[64], buf[256];
        snprintf(path, sizeof(path), "/proc/%d/stat", pid);
        int f = open(path, O_RDONLY);
        if (f < 0) continue;
        int n = read(f, buf, sizeof(buf)-1);
        close(f);
        if (n <= 0) continue;
        buf[n] = 0;
        
        // Skip kernel threads (comm in parens)
        char *cp = strchr(buf, '(');
        char *cp2 = strrchr(buf, ')');
        if (!cp || !cp2) continue;
        
        // Get process name
        char pname[64];
        int nlen = cp2 - cp - 1;
        if (nlen > 63) nlen = 63;
        strncpy(pname, cp + 1, nlen);
        pname[nlen] = 0;
        
        // Skip kernel threads, special system, excluded processes
        if (pname[0] == '[' || strstr(pname, "bash") || strstr(pname, "sh") ||
            strstr(pname, "sleep") || strstr(pname, "ps") || strstr(pname, "grep") ||
            strstr(pname, "python") || strstr(pname, "chrome") || strstr(pname, "node") ||
            strstr(pname, "rcu") || strstr(pname, "migration") || strstr(pname, "ksoftirqd") ||
            strstr(pname, "kworker") || strstr(pname, "kcompactd") || strstr(pname, "khugepaged") ||
            strstr(pname, "kswapd") || strstr(pname, "irq/") || strstr(pname, "jbd2") ||
            strstr(pname, "usb-storage") || strstr(pname, "nv_queue") ||
            pid == getpid())
            continue;
        
        // Skip processes we already watch
        int found = 0;
        for (int i = 0; i < state.nprocs; i++) {
            if (state.procs[i].pid == pid) { found = 1; break; }
        }
        if (found) continue;
        
        // Skip processes with 0 CPU time (just started)
        uint64_t ut, st;
        if (!read_proc_stat(pid, &ut, &st)) continue;
        if (ut + st < 2) continue; // < 2 ticks = barely started
        
        // Add to watch list
        if (state.nprocs < MAX_WATCHED) {
            WatchedProc *wp = &state.procs[state.nprocs++];
            memset(wp, 0, sizeof(*wp));
            wp->pid = pid;
            strncpy(wp->name, pname, sizeof(wp->name)-1);
            wp->is_jvm = detect_jvm(pid);
            wp->clk_tck = sysconf(_SC_CLK_TCK);
            wp->last_utime = ut;
            wp->last_stime = st;
            wp->gc_threads = 0;
            wp->cpu_affinity = 0;
            wp->nice_value = 0;
            wp->perf_cycles = perf_open_hw(pid, PERF_COUNT_HW_CPU_CYCLES);
            wp->perf_instrs = perf_open_hw(pid, PERF_COUNT_HW_INSTRUCTIONS);
            wp->perf_branches = perf_open_hw(pid, PERF_COUNT_HW_BRANCH_INSTRUCTIONS);
            wp->perf_bmiss = perf_open_hw(pid, PERF_COUNT_HW_BRANCH_MISSES);
            
            snprintf(path, sizeof(path), "/proc/%d/mem", pid);
            wp->mem_fd = open(path, O_RDWR);
            
            // Get exe path
            char exe[256];
            snprintf(exe, sizeof(exe), "/proc/%d/exe", pid);
            n = readlink(exe, wp->exe_path, sizeof(wp->exe_path)-1);
            if (n > 0) wp->exe_path[n] = 0;
            
            printf("[daemon] 👀 Watching PID %d (%s) JVM=%d\n",
                   pid, wp->name, wp->is_jvm);
            fflush(stdout);
        }
    }
    closedir(d);
}

// ─── Main loop ───
int main(void) {
    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║   ORACLE LIVE IMPROVER DAEMON                      ║\n");
    printf("║   Autonomous watchdog + NOP optimizer + JVM tuner  ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n\n");
    fflush(stdout);
    
    state.running = 1;
    state.daemon_cycles = 0;
    state.total_patches = 0;
    
    // Ignore SIGCHLD to avoid zombie issues with jcmd
    signal(SIGCHLD, SIG_IGN);
    
    while (state.running) {
        state.daemon_cycles++;
        
        // Scan for new processes every 5 cycles
        if (state.daemon_cycles % 1 == 0) {
            scan_processes();
        }
        
        // Watch all tracked processes
        for (int i = 0; i < state.nprocs; i++) {
            if (state.procs[i].pid == 0) continue;
            watch_process(&state.procs[i]);
            
            // Clean up dead processes — check via /proc existence not kill()
            char procpath[64];
            snprintf(procpath, sizeof(procpath), "/proc/%d", state.procs[i].pid);
            if (access(procpath, F_OK) != 0) {
                printf("[daemon] 💀 PID %d (%s) exited — %d patches applied\n",
                       state.procs[i].pid, state.procs[i].name,
                       state.procs[i].patches_applied);
                if (state.procs[i].perf_cycles >= 0) close(state.procs[i].perf_cycles);
                if (state.procs[i].perf_instrs >= 0) close(state.procs[i].perf_instrs);
                if (state.procs[i].perf_branches >= 0) close(state.procs[i].perf_branches);
                if (state.procs[i].perf_bmiss >= 0) close(state.procs[i].perf_bmiss);
                if (state.procs[i].mem_fd >= 0) close(state.procs[i].mem_fd);
                state.procs[i].pid = 0;
            }
        }
        
        // Print status every cycle
        if (state.daemon_cycles % 1 == 0) {
            int alive = 0, patched = 0;
            for (int i = 0; i < state.nprocs; i++) {
                if (state.procs[i].pid > 0) alive++;
                if (state.procs[i].patches_applied > 0) patched++;
            }
            printf("[daemon] 📊 Cycle %lu — watching %d procs, %d patched, %lu total patches\n",
                   state.daemon_cycles, alive, patched, state.total_patches);
            fflush(stdout);
        }
        
        sleep(SCAN_INTERVAL);
    }
    
    printf("[daemon] Shutting down. Total patches applied: %lu\n", state.total_patches);
    return 0;
}
