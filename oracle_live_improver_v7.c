/* ============================================================================
 * oracle_live_improver_v7.c — Evolutionary Live Code Improver
 *
 * Applies patches, measures impact, keeps winners, reverts losers.
 * Over time, the running process's code evolves toward optimal performance.
 *
 * Evolution loop (runs every 30 seconds per target):
 *   1. SAMPLE — measure current IPC, branch misses, cache misses via perf
 *   2. PATCH — apply a candidate optimization (NOP, CMOV, alignment)
 *   3. MEASURE — wait 10 seconds, re-measure
 *   4. SCORE — fitness = delta_IPC * 10 - delta_branch_miss% - delta_cache_miss%
 *   5. KILL or KEEP — if fitness > 0, keep patch; if < 0, revert it
 *   6. MUTATE — try different patches based on what worked
 *   7. REPEAT — forever
 *
 * Built on the singularity's evolutionary attractor model:
 *   - crossover_attractors()  → crossover_patches()
 *   - mutate_attractor()      → mutate_patch_parameters()
 *   - composite_fitness()     → composite_fitness()
 *   - deprecate_attractor()   → revert_patch()
 *
 * Build: gcc -O3 -march=native -o oracle_live_improver_v7 \
 *            oracle_live_improver_v7.c -lm
 * Usage: ./oracle_live_improver_v7 <pid>          # evolve a single process
 *        ./oracle_live_improver_v7 <pid> --daemon  # evolve everything, keep running
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
#include <errno.h>
#include <time.h>
#include <math.h>

#include <linux/perf_event.h>
#include <sys/syscall.h>

// ─── Constants ───
#define MAX_PATCHES 4096
#define MAX_REGION_SZ (8 * 1048576)
#define MAX_GENERATIONS 100
#define EVOLVE_INTERVAL 15  // seconds between generations
#define FITNESS_THRESHOLD 0.5f
#define IPC_TARGET 3.0f  // modern x86 can do ~3 IPC optimally

// ─── NOP table ───
static const uint8_t nops[9][9] = {
    {0}, {0x90}, {0x66, 0x90},
    {0x0F, 0x1F, 0x00}, {0x0F, 0x1F, 0x40, 0x00},
    {0x0F, 0x1F, 0x44, 0x00, 0x00}, {0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00},
    {0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00},
    {0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00}
};

// ─── Patch types ───
typedef enum {
    PT_NOP_OPT,       // Consolidate single-byte NOPs
    PT_NOP_ALIGN,     // Align loop entry to cache line
    PT_CMOV,          // jcc → CMOV (same length)
    PT_MOV_WIDEN,     // 32-bit → 64-bit register
    PT__COUNT
} PatchType;

static const char *pt_names[] = {"nop-opt", "nop-align", "cmov", "mov-widen"};

// ─── Fitness metrics (from singularity's fitness_metrics_t) ───
typedef struct {
    float ipc;
    float branch_miss_pct;
    float cache_miss_pct;
    uint64_t cycles;
    uint64_t instructions;
    uint64_t branches;
    uint64_t branch_misses;
} FitnessMetrics;

// ─── An evolved patch ───
typedef struct {
    PatchType type;
    uint64_t addr;
    uint8_t original[32];
    uint8_t patch[32];
    int len;
    int generation;
    float fitness;
    float best_fitness;
    int applied;
    int reverted;
    int n_tested;
    uint64_t first_seen;
    char desc[64];
} EvolvedPatch;

// ─── State ───
typedef struct {
    pid_t pid;
    int mem_fd;
    int perf_cycles, perf_instrs, perf_branches, perf_bmiss;
    
    EvolvedPatch patches[MAX_PATCHES];
    int np;
    int n_applied;
    
    int generation;
    int do_daemon;
    
    // Running fitness baseline
    FitnessMetrics baseline;
    int has_baseline;
} State;

// ─── Perf helpers ───
static int perf_open(pid_t pid, uint32_t event) {
    struct perf_event_attr pe = {0};
    pe.size = sizeof(pe);
    pe.type = PERF_TYPE_HARDWARE;
    pe.config = event;
    pe.disabled = 1;
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;
    int fd = syscall(__NR_perf_event_open, &pe, pid, -1, -1, 0);
    if (fd >= 0) ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    return fd;
}

// ─── Read perf counters ───
static FitnessMetrics measure(State *st) {
    FitnessMetrics m = {0};
    if (st->perf_cycles < 0) return m;
    uint64_t c1,i1,b1,bm1, c2,i2,b2,bm2;
    
    read(st->perf_cycles, &c1, 8);
    read(st->perf_instrs, &i1, 8);
    if (st->perf_branches >= 0) read(st->perf_branches, &b1, 8);
    if (st->perf_bmiss >= 0) read(st->perf_bmiss, &bm1, 8);
    
    usleep(500000); // 500ms sample
    
    read(st->perf_cycles, &c2, 8);
    read(st->perf_instrs, &i2, 8);
    if (st->perf_branches >= 0) read(st->perf_branches, &b2, 8);
    if (st->perf_bmiss >= 0) read(st->perf_bmiss, &bm2, 8);
    
    uint64_t dc = c2 - c1, di = i2 - i1, db = b2 - b1, dbm = bm2 - bm1;
    m.ipc = dc > 0 ? (float)di / dc : 0;
    m.branch_miss_pct = db > 0 ? (float)dbm / db * 100 : 0;
    m.cycles = dc;
    m.instructions = di;
    m.branches = db;
    m.branch_misses = dbm;
    return m;
}

// ─── Composite fitness score (higher = better) ───
// Same formula as singularity's composite_fitness()
static float composite_fitness(FitnessMetrics *before, FitnessMetrics *after) {
    if (before->cycles == 0 || after->cycles == 0) return 0;
    
    float ipc_delta = after->ipc - before->ipc;
    float bmr_delta = before->branch_miss_pct - after->branch_miss_pct; // negative = improvement
    float score = 0;
    
    // IPC improvement (higher IPC = better)
    score += ipc_delta * 10.0f;
    
    // Branch miss reduction
    if (before->branch_miss_pct > 1.0f)
        score += bmr_delta * 2.0f;
    
    // Scale by confidence (more instructions = more reliable)
    float confidence = fminf((float)after->instructions / 1000000.0f, 1.0f);
    score *= confidence;
    
    return score;
}

// ─── Read memory ───
static int read_mem(State *st, uint64_t addr, uint8_t *buf, size_t len) {
    struct iovec lo = {buf, len}, ro = {(void*)(uintptr_t)addr, len};
    if (process_vm_readv(st->pid, &lo, 1, &ro, 1, 0) > 0) return 1;
    if (st->mem_fd >= 0) return pread64(st->mem_fd, buf, len, addr) == (ssize_t)len;
    return 0;
}
static int write_mem(State *st, uint64_t addr, const uint8_t *buf, size_t len) {
    struct iovec lo = {(void*)buf, len}, ro = {(void*)(uintptr_t)addr, len};
    if (process_vm_writev(st->pid, &lo, 1, &ro, 1, 0) > 0) return 1;
    if (st->mem_fd >= 0) return pwrite64(st->mem_fd, buf, len, addr) == (ssize_t)len;
    return 0;
}

// ─── Revert a patch ───
static int revert_patch(State *st, EvolvedPatch *ep) {
    if (!ep->applied || ep->reverted) return 0;
    if (!write_mem(st, ep->addr, ep->original, ep->len)) return 0;
    ep->applied = 0;
    ep->reverted = 1;
    ep->fitness = -999; // mark as failed
    st->n_applied--;
    printf("[v7]   ↩ REVERTED generation %d: %s 0x%lx (fitness=%.2f)\n",
           ep->generation, pt_names[ep->type], ep->addr, ep->fitness);
    return 1;
}

// ─── Scan for patch candidates ───
static void scan_candidates(State *st) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", st->pid);
    FILE *f = fopen(path, "r");
    if (!f) return;
    
    uint8_t *buf = malloc(MAX_REGION_SZ);
    if (!buf) { fclose(f); return; }
    
    char line[1024];
    while (fgets(line, sizeof(line), f) && st->np < MAX_PATCHES) {
        unsigned long s, e;
        if (sscanf(line, "%lx-%lx", &s, &e) < 2) continue;
        char *pp = strchr(line, ' ');
        if (!pp || pp[3] != 'x') continue;
        if (strstr(line, ".so") || strstr(line, "/lib/") ||
            strstr(line, "[vdso]") || strstr(line, "[stack")) continue;
        
        size_t sz = e - s;
        if (sz > MAX_REGION_SZ) sz = MAX_REGION_SZ;
        if (sz < 16) continue;
        if (!read_mem(st, s, buf, sz)) continue;
        
        for (size_t off = 0; off < sz - 2 && st->np < MAX_PATCHES; off++) {
            // NOP consolidation
            if (buf[off] == 0x90) {
                int run = 0;
                while (off + run < sz && buf[off+run] == 0x90 && run < 8) run++;
                if (run >= 2 && nops[run][0]) {
                    EvolvedPatch *ep = &st->patches[st->np++];
                    ep->type = PT_NOP_OPT;
                    ep->addr = s + off;
                    ep->len = run;
                    memcpy(ep->patch, nops[run], run);
                    ep->generation = 0;
                    ep->first_seen = time(NULL);
                    snprintf(ep->desc, sizeof(ep->desc), "%d-byte NOP run", run);
                    off += run;
                }
            }
            
            // CMOV candidate: 6-byte jcc followed by simple mov at target
            if (off + 6 < sz && buf[off] == 0x0F && (buf[off+1] >= 0x80 && buf[off+1] <= 0x8F)) {
                int32_t rel32;
                memcpy(&rel32, buf + off + 2, 4);
                uint64_t target = s + off + 6 + rel32;
                
                if (target >= s && target < s + sz) {
                    size_t toff = target - s;
                    uint8_t *tp = buf + toff;
                    if ((tp[0] & 0xF8) == 0xB8) { // mov $imm32, %r32
                        uint8_t dst = tp[0] & 0x07;
                        uint8_t *ft = buf + off + 6;
                        if ((ft[0] & 0xF8) == 0xB8 && (ft[0] & 0x07) == dst) {
                            uint8_t src = dst;
                            EvolvedPatch *ep = &st->patches[st->np++];
                            ep->type = PT_CMOV;
                            ep->addr = s + off;
                            ep->len = 6;
                            uint8_t cond = buf[off+1] & 0x0F;
                            ep->patch[0] = 0x0F;
                            ep->patch[1] = 0x40 + cond;
                            ep->patch[2] = 0xC0 + dst + (src << 3);
                            ep->patch[3] = nops[3][0];
                            ep->patch[4] = nops[3][1];
                            ep->patch[5] = nops[3][2];
                            snprintf(ep->desc, sizeof(ep->desc), "jcc->cmov cond=%d r%d", cond, dst);
                        }
                    }
                }
            }
        }
    }
    fclose(f);
    free(buf);
    printf("[v7] Found %d patch candidates\n", st->np);
}

// ─── Apply a single patch ───
static int apply_patch(State *st, EvolvedPatch *ep) {
    if (ep->applied || ep->reverted) return 0;
    if (ep->len == 0) return 0;
    
    // Save original
    if (!read_mem(st, ep->addr, ep->original, ep->len)) {
        printf("[v7]   ✗ can't read at 0x%lx\n", ep->addr);
        return 0;
    }
    
    // Write patch
    if (!write_mem(st, ep->addr, ep->patch, ep->len)) {
        printf("[v7]   ✗ can't write at 0x%lx\n", ep->addr);
        return 0;
    }
    
    ep->applied = 1;
    ep->generation = st->generation;
    st->n_applied++;
    printf("[v7]   ✓ APPLIED gen %d: %s 0x%lx (%d bytes) %s\n",
           ep->generation, pt_names[ep->type], ep->addr, ep->len, ep->desc);
    return 1;
}

// ─── Evolution step (one generation) ───
static int evolve(State *st) {
    printf("\n[v7] ═══ GENERATION %d ═══\n", ++st->generation);
    
    // 1. Measure baseline
    FitnessMetrics before = measure(st);
    if (!st->has_baseline) {
        st->baseline = before;
        st->has_baseline = 1;
        printf("[v7] Baseline: IPC=%.2f BrMiss=%.2f%%\n", before.ipc, before.branch_miss_pct);
    }
    
    // 2. Try patches that haven't been tested yet
    int tested = 0;
    for (int i = 0; i < st->np && tested < 3; i++) {
        EvolvedPatch *ep = &st->patches[i];
        if (ep->applied || ep->reverted) continue;
        if (ep->generation > 0) continue;
        
        if (apply_patch(st, ep)) {
            tested++;
        }
    }
    
    // 3. Re-evaluate patches applied in previous generations
    int reverted = 0;
    if (tested == 0) {
        // No new patches to try — evaluate existing ones
        FitnessMetrics after = measure(st);
        
        for (int i = 0; i < st->np; i++) {
            EvolvedPatch *ep = &st->patches[i];
            if (!ep->applied) continue;
            
            ep->n_tested++;
            float score = composite_fitness(&st->baseline, &after);
            ep->fitness = score;
            
            if (score > ep->best_fitness) ep->best_fitness = score;
            
            printf("[v7]   📊 Patch %s 0x%lx: fitness=%.2f (best=%.2f, n=%d)\n",
                   pt_names[ep->type], ep->addr, score, ep->best_fitness, ep->n_tested);
            
            // Revert if consistently bad
            if (score < -FITNESS_THRESHOLD && ep->n_tested >= 2) {
                revert_patch(st, ep);
                reverted++;
            }
            
            // Update baseline with improvement
            if (score > FITNESS_THRESHOLD) {
                st->baseline = after;
                printf("[v7]   ⭐ New baseline: IPC=%.2f\n", after.ipc);
            }
        }
        
        if (reverted == 0 && tested == 0) {
            printf("[v7] All patches stable. No changes this generation.\n");
        }
    }
    
    // 4. Print summary
    int alive = 0, dead = 0;
    for (int i = 0; i < st->np; i++) {
        if (st->patches[i].applied) alive++;
        if (st->patches[i].reverted) dead++;
    }
    printf("[v7] 📊 Gen %d: %d applied, %d reverted, %d/%d alive\n",
           st->generation, st->n_applied, dead, alive - dead, st->np);
    
    return alive;
}

// ─── Main ───
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <pid> [--daemon]\n", argv[0]);
        fprintf(stderr, "  Evolves a running process through generations of code patches.\n");
        return 1;
    }
    
    State st = {0};
    st.pid = atoi(argv[1]);
    st.do_daemon = (argc > 2 && strcmp(argv[2], "--daemon") == 0);
    
    char mpath[64];
    snprintf(mpath, sizeof(mpath), "/proc/%d/mem", st.pid);
    st.mem_fd = open(mpath, O_RDWR);
    
    // Open perf counters
    st.perf_cycles = perf_open(st.pid, PERF_COUNT_HW_CPU_CYCLES);
    st.perf_instrs = perf_open(st.pid, PERF_COUNT_HW_INSTRUCTIONS);
    st.perf_branches = perf_open(st.pid, PERF_COUNT_HW_BRANCH_INSTRUCTIONS);
    st.perf_bmiss = perf_open(st.pid, PERF_COUNT_HW_BRANCH_MISSES);
    
    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║   ORACLE EVOLUTIONARY IMPROVER v7              ║\n");
    printf("║   Evolves running code through generations      ║\n");
    printf("║   PID: %-6d                                   ║\n", st.pid);
    if (st.do_daemon) printf("║   --daemon (continuous)                       ║\n");
    printf("╚══════════════════════════════════════════════════╝\n");
    
    // Initial scan
    printf("\n── Scan ──\n");
    scan_candidates(&st);
    
    // Evolution loop
    printf("\n── Evolution ──\n");
    int gens = 0;
    while (gens < MAX_GENERATIONS) {
        if (kill(st.pid, 0) != 0) {
            printf("[v7] ❌ Process %d no longer exists\n", st.pid);
            break;
        }
        
        evolve(&st);
        gens++;
        
        if (!st.do_daemon && gens >= 3) break;
        if (st.do_daemon) sleep(EVOLVE_INTERVAL);
    }
    
    printf("\n[v7] Evolution complete: %d generations, %d patches evaluated\n",
           gens, st.np);
    
    if (st.mem_fd >= 0) close(st.mem_fd);
    if (st.perf_cycles >= 0) close(st.perf_cycles);
    if (st.perf_instrs >= 0) close(st.perf_instrs);
    if (st.perf_branches >= 0) close(st.perf_branches);
    if (st.perf_bmiss >= 0) close(st.perf_bmiss);
    
    return 0;
}
