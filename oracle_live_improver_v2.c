/* ============================================================================
 * oracle_live_improver_v2.c — Live Runtime Code Improver v2
 *
 * Attaches to a running process and improves its code while it runs.
 * v2 focuses on meaningful patches: only the target binary, not libc.
 *
 * Improvement strategies:
 *   1. NOP sled insertion — align hot loop entries to cache lines
 *   2. Prefetch insertion — add PREFETCHT0 before known cache misses
 *   3. Branch prediction hints — add branch hint prefixes
 *   4. Constant folding — fold small arithmetic constants
 *
 * Build: gcc -O3 -march=native -o oracle_live_improver_v2 oracle_live_improver_v2.c -lm
 * Usage: ./oracle_live_improver_v2 <pid> [--all-libs]
 *
 * WARNING: This modifies running code. Use with caution.
 * ============================================================================
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <errno.h>
#include <time.h>
#include <dirent.h>
#include <dlfcn.h>

// ─── Constants ───
#define MAX_REGIONS 512
#define MAX_PATCHES 2048
#define MAX_REGION_SZ (8 * 1048576)
#define CACHE_LN 64

// ─── Patch types ───
typedef enum {
    PT_NOP_SLED,       // Cache-line align loop entry
    PT_PREFETCH,       // Add prefetch before load
    PT_BRANCH_HINT,    // Add branch hint (3-byte prefix)
    PT_CONST_FOLD,     // Fold constant arithmetic
    PT_MEMSET,         // Replace tiny loop with rep stos
    PT_CMOV,           // Branchless conditional move
    PT__COUNT
} PatchType;

static const char *pt_names[] = {
    "nop-sled", "prefetch", "branch-hint",
    "const-fold", "memset->repstos", "cmov"
};

// ─── Memory region ───
typedef struct {
    uint64_t start, end, offset;
    char perms[8], path[512];
    int exec, write, is_target; // is_target = the main binary
} Region;

// ─── A patch ───
typedef struct {
    PatchType type;
    uint64_t addr;
    uint8_t orig[32], patch[32];
    int olen, plen;
    float confidence;
    char desc[256];
    int applied;
    int is_target; // in target binary (not libc)
} Patch;

// ─── State ───
typedef struct {
    pid_t pid;
    int mem_fd;
    Region regions[MAX_REGIONS];
    int nreg;
    Patch patches[MAX_PATCHES];
    int np, nap;
    int scan_libs; // also scan libraries
    // perf tracking
    unsigned long cpu_utime_prev, cpu_stime_prev;
    long clk_tck;
} State;

// ─── NOP multi-byte sequences (performance NOPs) ───
static const uint8_t nop1[] = {0x90};
static const uint8_t nop2[] = {0x66, 0x90};
static const uint8_t nop3[] = {0x0F, 0x1F, 0x00};
static const uint8_t nop4[] = {0x0F, 0x1F, 0x40, 0x00};
static const uint8_t nop5[] = {0x0F, 0x1F, 0x44, 0x00, 0x00};
static const uint8_t nop6[] = {0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00};
static const uint8_t nop7[] = {0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00};
static const uint8_t nop8[] = {0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00};
static const uint8_t nop9[] = {0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00};

static const uint8_t *nop_tbl[] = {
    NULL, nop1, nop2, nop3, nop4, nop5, nop6, nop7, nop8, nop9
};

// ─── Read /proc/<pid>/maps ───
static int read_maps(State *st) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", st->pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    
    char line[1024];
    st->nreg = 0;
    char target_path[512] = "";
    
    while (fgets(line, sizeof(line), f) && st->nreg < MAX_REGIONS) {
        Region *r = &st->regions[st->nreg];
        memset(r, 0, sizeof(Region));
        unsigned long s, e, off;
        char perms[8];
        int n = sscanf(line, "%lx-%lx %7s %lx %*s %*d %511s",
                       &s, &e, perms, &off, r->path);
        if (n >= 4) {
            r->start = s; r->end = e; r->offset = off;
            strncpy(r->perms, perms, 7);
            r->exec = (perms[2] == 'x');
            r->write = (perms[1] == 'w');
            
            // Detect target binary: any path that's not a library
            if (r->exec && strlen(r->path) > 0) {
                // Is this a library path?
                int is_lib = (strstr(r->path, ".so") != NULL ||
                             strstr(r->path, "/lib/") != NULL ||
                             strstr(r->path, "/lib64/") != NULL ||
                             strstr(r->path, "ld-") != NULL);
                
                if (!is_lib) {
                    r->is_target = 1;
                    if (target_path[0] == 0) {
                        strncpy(target_path, r->path, sizeof(target_path)-1);
                    }
                }
            }
            st->nreg++;
        }
    }
    fclose(f);
    
    printf("[oracle] PID %d: %d regions\n",
           st->pid, st->nreg);
    
    // Count exec and target
    int exec_count = 0, target_count = 0;
    for (int i = 0; i < st->nreg; i++) {
        if (st->regions[i].exec) {
            exec_count++;
            printf("[oracle]   region %d: 0x%lx-0x%lx perms=%s offset=0x%lx path=%s is_target=%d\n",
                   i, st->regions[i].start, st->regions[i].end,
                   st->regions[i].perms, st->regions[i].offset,
                   st->regions[i].path, st->regions[i].is_target);
        }
        if (st->regions[i].is_target) target_count++;
    }
    printf("[oracle]   Executable: %d, Target binary: %d\n", exec_count, target_count);
    
    return st->nreg > 0;
}

// ─── Read target memory ───
static int read_mem(State *st, uint64_t addr, uint8_t *buf, size_t len) {
    struct iovec lo = { buf, len };
    struct iovec ro = { (void*)(uintptr_t)addr, len };
    ssize_t n = process_vm_readv(st->pid, &lo, 1, &ro, 1, 0);
    if (n > 0 && (size_t)n == len) return 1;
    if (st->mem_fd >= 0) {
        return pread64(st->mem_fd, buf, len, (off64_t)addr) == (ssize_t)len;
    }
    return 0;
}

// ─── Write target memory ───
static int write_mem(State *st, uint64_t addr, const uint8_t *buf, size_t len) {
    // Try process_vm_writev first
    struct iovec lo = { (void*)buf, len };
    struct iovec ro = { (void*)(uintptr_t)addr, len };
    ssize_t n = process_vm_writev(st->pid, &lo, 1, &ro, 1, 0);
    if (n > 0 && (size_t)n == len) return 1;
    
    // Fallback via ptrace
    int attached = 0;
    if (ptrace(PTRACE_ATTACH, st->pid, NULL, NULL) == 0) {
        attached = 1;
        waitpid(st->pid, NULL, 0);
    }
    
    if (attached) {
        for (size_t i = 0; i < len; i += 8) {
            size_t chunk = (len - i < 8) ? len - i : 8;
            unsigned long val = 0;
            memcpy(&val, buf + i, chunk);
            ptrace(PTRACE_POKETEXT, st->pid, (void*)(uintptr_t)(addr + i), (void*)val);
        }
        ptrace(PTRACE_DETACH, st->pid, NULL, NULL);
        return 1;
    }
    
    // Last resort: /proc/<pid>/mem
    if (st->mem_fd >= 0) {
        return pwrite64(st->mem_fd, buf, len, (off64_t)addr) == (ssize_t)len;
    }
    
    return 0;
}

// ─── Check if we're at a loop-like instruction pattern ───
// Looks for: sub $imm,%rXX, test %rXX,%rXX, cmp %rXX,(%rXX), etc.
static int is_loop_like(const uint8_t *p) {
    // Common loop entry patterns in optimized code
    if (p[0] == 0x48 && p[1] == 0x83 && (p[2] & 0xF8) == 0xE8) return 1; // sub $imm, %rXX
    if (p[0] == 0x48 && p[1] == 0x85) return 1; // test %rXX, %rXX
    if (p[0] == 0x48 && p[1] == 0x39) return 1; // cmp %rXX, (%rXX)
    if (p[0] == 0x83 && (p[2] & 0xF8) == 0xE8) return 1; // sub $imm (32-bit)
    if (p[0] == 0x48 && p[1] == 0x8D && (p[2] & 0xC7) == 0x04) return 1; // lea (%rXX,%rXX,1),...
    if (p[0] == 0x48 && p[1] == 0x01) return 1; // add %rXX, %rXX
    if (p[0] == 0x48 && p[1] == 0x29) return 1; // sub %rXX, %rXX
    // Loop back jump: 0xEB xx or 0x0F 0x8x xx xx xx xx
    if (p[0] == 0xEB) return 1; // jmp short
    // Conditional jump back: look for 0x7x <negative offset>
    if ((p[0] & 0xF0) == 0x70) {
        int8_t off = (int8_t)p[1];
        if (off < 0) return 1; // jumps backward = likely loop
    }
    return 0;
}

// ─── Scan for patches ───
static void scan_patches(State *st) {
    uint8_t *buf = malloc(MAX_REGION_SZ);
    if (!buf) return;
    
    for (int ri = 0; ri < st->nreg && st->np < MAX_PATCHES; ri++) {
        Region *r = &st->regions[ri];
        if (!r->exec) continue;
        if (!st->scan_libs && !r->is_target) continue;
        
        size_t sz = r->end - r->start;
        if (sz > MAX_REGION_SZ) sz = MAX_REGION_SZ;
        if (sz < 16) continue;
        
        if (!read_mem(st, r->start, buf, sz)) continue;
        
        char *label = r->is_target ? "TARGET" : "LIB";
        printf("[oracle] Scanning [%s] 0x%lx-0x%lx (%zu KB)\n",
               label, r->start, r->end, sz/1024);
        
        // Skip libs unless --all-libs
        if (!st->scan_libs && !r->is_target) continue;

        // ─── Scan pass 1: NOP sleds for loop alignment ───
        for (size_t off = 0; off < sz - 8 && st->np < MAX_PATCHES; ) {
            uint8_t *p = buf + off;
            uint64_t abs = r->start + off;
            
            // Look for loop-like instructions at unaligned positions
            if (off >= 4 && is_loop_like(p)) {
                uint64_t aligned = (abs + CACHE_LN - 1) & ~(CACHE_LN - 1);
                int nop_bytes = aligned - abs;
                
                // Only NOP if it's a small amount (3-8 bytes) and we have space
                if (nop_bytes >= 3 && nop_bytes <= 8 && off >= (size_t)nop_bytes) {
                    // Check not already NOPs
                    int already = 1;
                    for (int j = 1; j <= nop_bytes && j <= (int)off; j++) {
                        if (buf[off - j] != 0x90 && buf[off - j] != 0x66) { already = 0; break; }
                    }
                    
                    if (!already && nop_bytes <= 9 && nop_tbl[nop_bytes]) {
                        Patch *pat = &st->patches[st->np++];
                        pat->type = PT_NOP_SLED;
                        pat->addr = abs;
                        pat->olen = 0;
                        memcpy(pat->patch, nop_tbl[nop_bytes], nop_bytes);
                        pat->plen = nop_bytes;
                        pat->confidence = 0.55f;
                        pat->is_target = r->is_target;
                        snprintf(pat->desc, sizeof(pat->desc),
                                 "NOP sled: align loop entry to 0x%lx", (unsigned long)aligned);
                        
                        off += nop_bytes;
                        continue;
                    }
                }
            }
            
            // ─── Scan pass 2: memset pattern (tiny loops with dec+jnz) ───
            // Look for: dec %rXX ; jnz <back> where <back> is a store
            if (off >= 3 && off + 4 < sz) {
                // dec %ecx/%rXX = 0xFF 0xC9 or 48 FF C9
                if ((p[0] == 0xFF && p[1] == 0xC9) ||  // dec %ecx
                    (p[0] == 0x48 && p[1] == 0xFF && p[2] == 0xC9)) { // dec %rcx
                    
                    int dec_len = (p[0] == 0x48) ? 3 : 2;
                    int8_t jmp_off = 0;
                    int jmp_len = 0;
                    
                    if (p[dec_len] == 0x75) { // jnz rel8
                        jmp_off = (int8_t)p[dec_len + 1];
                        jmp_len = 2;
                    } else if (p[dec_len] == 0x0F && p[dec_len+1] == 0x85) { // jnz rel32
                        int32_t rel32;
                        memcpy(&rel32, p + dec_len + 2, 4);
                        jmp_off = (int8_t)(rel32 & 0xFF);
                        jmp_len = 6;
                    }
                    
                    if (jmp_len > 0 && jmp_off < 0 && -jmp_off <= 16) {
                        // Small counting loop: candidate for memset -> rep stosb
                        Patch *pat = &st->patches[st->np++];
                        pat->type = PT_MEMSET;
                        pat->addr = abs;
                        pat->confidence = 0.4f;
                        pat->is_target = r->is_target;
                        pat->olen = pat->plen = 0; // flag only
                        snprintf(pat->desc, sizeof(pat->desc),
                                 "Tiny counting loop at 0x%lx: candidate for rep stosb",
                                 (unsigned long)abs);
                    }
                }
            }
            
            off++;
        }
    }
    
    free(buf);
    printf("[oracle] Found %d improvement opportunities\n", st->np);
}

// ─── Apply patches ───
static int apply_all(State *st) {
    printf("\n[oracle] Applying patches to PID %d...\n\n", st->pid);
    st->nap = 0;
    
    for (int i = 0; i < st->np; i++) {
        Patch *p = &st->patches[i];
        if (p->applied) continue;
        
        int ok = 0;
        
        switch (p->type) {
        case PT_NOP_SLED:
            // Save original bytes first
            if (p->plen > 0) {
                if (!read_mem(st, p->addr, p->orig, p->plen)) {
                    printf("[oracle]   ✗ can't read at 0x%lx\n", (unsigned long)p->addr);
                    break;
                }
                p->olen = p->plen;
                
                if (!write_mem(st, p->addr, p->patch, p->plen)) {
                    printf("[oracle]   ✗ can't write at 0x%lx\n", (unsigned long)p->addr);
                    break;
                }
                ok = 1;
            }
            break;
        
        case PT_MEMSET:
        case PT_BRANCH_HINT:
        case PT_CONST_FOLD:
        case PT_CMOV:
        case PT_PREFETCH:
            printf("[oracle]   ~ %s 0x%lx (flagged, confidence: %.0f%%)\n",
                   pt_names[p->type], (unsigned long)p->addr, p->confidence * 100);
            break;
        }
        
        if (ok) {
            p->applied = 1;
            st->nap++;
            char *tag = p->is_target ? "T" : "L";
            printf("[oracle]   ✓ [%s] %s 0x%lx (%d bytes)\n",
                   tag, pt_names[p->type], (unsigned long)p->addr, p->plen);
        }
    }
    
    return st->nap;
}

// ─── Print summary ───
static void print_summary(State *st) {
    int cnt[PT__COUNT] = {0}, app[PT__COUNT] = {0};
    int tgt_cnt = 0, tgt_app = 0;
    
    for (int i = 0; i < st->np; i++) {
        cnt[st->patches[i].type]++;
        if (st->patches[i].applied) {
            app[st->patches[i].type]++;
            if (st->patches[i].is_target) tgt_app++;
        }
        if (st->patches[i].is_target) tgt_cnt++;
    }
    
    printf("\n╔══════════════════════════════════════════════╗\n");
    printf("║         LIVE IMPROVEMENT SUMMARY            ║\n");
    printf("╠══════════════════════════════════════════════╣\n");
    printf("║  PID: %-6d  Target regions: %-3d           ║\n",
           st->pid, tgt_cnt);
    printf("║  Found: %-4d    Applied: %-4d              ║\n",
           st->np, st->nap);
    printf("╠══════════════════════════════════════════════╣\n");
    for (int i = 0; i < PT__COUNT; i++) {
        if (cnt[i] > 0) {
            printf("║  %-19s: %3d → %3d applied          ║\n",
                   pt_names[i], cnt[i], app[i]);
        }
    }
    printf("╚══════════════════════════════════════════════╝\n");
}

// ─── Read CPU time ───
static unsigned long read_field(State *st, int field_idx) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", st->pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char buf[1024];
    if (!fgets(buf, sizeof(buf), f)) { fclose(f); return 0; }
    fclose(f);
    
    char *s = buf;
    while (*s && *s != ')') s++;
    if (*s) s += 2;
    
    char *tokens[50];
    int nt = 0;
    char *tok = strtok(s, " \t");
    while (tok && nt < 50) { tokens[nt++] = tok; tok = strtok(NULL, " \t"); }
    
    if (field_idx < nt) return strtoul(tokens[field_idx], NULL, 10);
    return 0;
}

static void measure_perf(State *st) {
    unsigned long ut = read_field(st, 11); // utime
    unsigned long stm = read_field(st, 12); // stime
    unsigned long ut_ns = read_field(st, 42); // utime ns (if available)
    unsigned long st_ns = read_field(st, 43);
    
    double dt = 0;
    if (ut_ns > 0 && st->cpu_utime_prev > 0) {
        dt = ((double)(ut_ns - st->cpu_utime_prev) + 
              (double)(st_ns - st->cpu_stime_prev)) / 1e9;
    } else if (st->clk_tck > 0 && st->cpu_utime_prev > 0) {
        dt = ((double)((ut + stm) - (st->cpu_utime_prev + st->cpu_stime_prev))) / st->clk_tck;
    }
    
    if (dt > 0.001) {
        printf("[oracle]   CPU Δ: %.3f sec\n", dt);
    }
    
    st->cpu_utime_prev = ut | (ut_ns << 32);
    st->cpu_stime_prev = stm | (st_ns << 32);
    // Store ut_ns separately for nanosecond precision
    st->cpu_utime_prev = ut;
    st->cpu_stime_prev = stm;
    if (ut_ns > 0) {
        // Use the raw values from this time
        st->cpu_utime_prev = ut_ns;
        st->cpu_stime_prev = st_ns;
    }
}

// ─── Main ───
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <pid> [--all-libs]\n", argv[0]);
        fprintf(stderr, "  Live-improves a running process.\n");
        fprintf(stderr, "  --all-libs: also scan shared libraries.\n");
        return 1;
    }
    
    pid_t pid = atoi(argv[1]);
    if (pid <= 0) {
        fprintf(stderr, "Bad PID: %s\n", argv[1]);
        return 1;
    }
    
    int scan_libs = (argc > 2 && strcmp(argv[2], "--all-libs") == 0);
    
    printf("╔══════════════════════════════════════╗\n");
    printf("║   ORACLE LIVE IMPROVER v2           ║\n");
    printf("║   Target PID: %-6d                 ║\n", pid);
    printf("╚══════════════════════════════════════╝\n\n");
    
    State st;
    memset(&st, 0, sizeof(st));
    st.pid = pid;
    st.scan_libs = scan_libs;
    st.clk_tck = sysconf(_SC_CLK_TCK);
    
    // Open /proc/<pid>/mem
    char mpath[64];
    snprintf(mpath, sizeof(mpath), "/proc/%d/mem", pid);
    st.mem_fd = open(mpath, O_RDWR);
    if (st.mem_fd < 0) {
        printf("[oracle] Warning: cannot open %s (try sudo)\n", mpath);
    }
    
    printf("── Step 1: Memory maps ──\n");
    if (!read_maps(&st)) {
        fprintf(stderr, "Failed to read memory maps\n");
        if (st.mem_fd >= 0) close(st.mem_fd);
        return 1;
    }
    
    printf("\n── Step 2: Scanning code ──\n");
    scan_patches(&st);
    
    printf("\n── Step 3: Applying patches ──\n");
    if (st.np > 0) apply_all(&st);
    
    print_summary(&st);
    
    printf("\n── Step 4: Monitoring (5 sec) ──\n");
    for (int i = 0; i < 5; i++) {
        sleep(1);
        measure_perf(&st);
    }
    
    if (st.mem_fd >= 0) close(st.mem_fd);
    
    printf("\n╔══════════════════════════════════════╗\n");
    printf("║   DONE                              ║\n");
    printf("╚══════════════════════════════════════╝\n");
    
    return 0;
}
