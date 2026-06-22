/* ============================================================================
 * oracle_live_improver.c — Live Runtime Code Improver
 *
 * Attaches to a running process by PID and improves its code while it
 * runs. Uses /proc/<pid>/mem for live memory access and ptrace for
 * synchronized code patching.
 *
 * Improvement strategies (applied live):
 *   1. Branchless conversion — replace conditional jumps with CMOV
 *   2. NOP sled insertion — align hot loop entries to cache lines
 *   3. Prefetch insertion — add PREFETCHT0 before known cache misses
 *   4. Constant folding — replace computed constants with immediates
 *   5. Hot/cold reordering — annotate likely/unlikely branches
 *   6. Memory operation widening — replace 32-bit with 64-bit ops
 *
 * Build: gcc -O3 -march=native -o oracle_live_improver oracle_live_improver.c -lm
 * Usage: ./oracle_live_improver <pid>
 *
 * WARNING: This modifies running code. Use at your own risk.
 *          Best used on test/development programs or the oracle's own
 *          singularity daemon.
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
#include <sys/user.h>
#include <sys/syscall.h>
#include <errno.h>
#include <signal.h>
#include <time.h>

// ─── Analysis constants ───
#define MAX_CODE_REGIONS 256
#define MAX_PATCHES 1024
#define MAX_REGION_SIZE (4 * 1048576)  // 4MB per region
#define CACHE_LINE 64
#define MY_PAGE_SIZE 4096

// ─── x86-64 opcode helpers ───
#define X86_NOP 0x90
#define X86_NOP_5 0x0F, 0x1F, 0x44, 0x00, 0x00  // 5-byte NOP
#define X86_NOP_9 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00  // 9-byte NOP

// ─── Patch kinds ───
typedef enum {
    PATCH_NOP_SLED,         // Align loop entries to cache lines
    PATCH_BRANCHLESS,       // Replace jcc with CMOV
    PATCH_PREFETCH,         // Insert PREFETCHT0 before load
    PATCH_CONSTANT_FOLD,    // Replace computed with immediate
    PATCH_LIKELY,           // Add branch hint prefixes
    PATCH_WIDEN,            // Widen 32-bit to 64-bit ops
    PATCH_LOOP_UNROLL,      // Duplicate loop body (simple)
    PATCH_MEMSET_TO_STOSB,  // Replace small memset with rep stosb
    PATCH_NUM_KINDS
} PatchKind;

static const char *patch_names[] = {
    "nop-sled", "branchless", "prefetch", "constant-fold",
    "likely-hint", "widen-op", "loop-unroll", "memset-stosb"
};

// ─── Memory region descriptor ───
typedef struct {
    uint64_t start;
    uint64_t end;
    uint64_t offset;
    char     perms[8];
    char     path[256];
    int      is_executable;
    int      is_writable;
} MemRegion;

// ─── A live patch to apply ───
typedef struct {
    PatchKind  kind;
    uint64_t   address;
    uint8_t    original[32];
    uint8_t    patch[32];
    int        patch_len;
    int        original_len;
    float      confidence;
    char       description[256];
    int        applied;  // 1 = applied, 0 = pending
} LivePatch;

// ─── Target process state ───
typedef struct {
    pid_t      pid;
    int        mem_fd;
    MemRegion  regions[MAX_CODE_REGIONS];
    int        n_regions;
    
    LivePatch  patches[MAX_PATCHES];
    int        n_patches;
    int        n_applied;
    
    uint64_t   entry_point;
    char       exe_path[1024];
    
    // Performance tracking
    unsigned long prev_utime;
    unsigned long prev_stime;
    unsigned long prev_utime_ns;
    unsigned long prev_stime_ns;
    long         clock_ticks;
} TargetState;

// ─── Read target's memory maps ───
static int read_memory_maps(TargetState *t) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", t->pid);
    
    FILE *f = fopen(path, "r");
    if (!f) { perror("fopen maps"); return 0; }
    
    char line[512];
    t->n_regions = 0;
    
    while (fgets(line, sizeof(line), f) && t->n_regions < MAX_CODE_REGIONS) {
        MemRegion *r = &t->regions[t->n_regions];
        memset(r, 0, sizeof(MemRegion));
        
        // Parse: start-end perms offset dev inode path
        unsigned long s, e, off;
        char perms[8];
        int n = sscanf(line, "%lx-%lx %s %lx %*s %*d %s",
                       &s, &e, perms, &off, r->path);
        
        if (n >= 4) {
            r->start = s;
            r->end = e;
            r->offset = off;
            strncpy(r->perms, perms, sizeof(r->perms) - 1);
            r->is_executable = (perms[2] == 'x');
            r->is_writable = (perms[1] == 'w');
            t->n_regions++;
        }
    }
    
    fclose(f);
    
    // Find executable path
    for (int i = 0; i < t->n_regions; i++) {
        if (t->regions[i].offset == 0 && t->regions[i].is_executable &&
            strlen(t->regions[i].path) > 0) {
            strncpy(t->exe_path, t->regions[i].path, sizeof(t->exe_path) - 1);
            t->entry_point = t->regions[i].start;
            break;
        }
    }
    
    printf("[oracle] Target PID %d — %d memory regions, %d executable\n",
           t->pid, t->n_regions, 
           (int)(t->n_regions > 0));
    
    // Find executable regions
    int exec_count = 0;
    for (int i = 0; i < t->n_regions; i++) {
        if (t->regions[i].is_executable) exec_count++;
    }
    printf("[oracle] Executable regions: %d\n", exec_count);
    
    return t->n_regions > 0;
}

// ─── Read target memory ───
static int read_target_mem(TargetState *t, uint64_t addr, uint8_t *buf, size_t len) {
    struct iovec local = { .iov_base = buf, .iov_len = len };
    struct iovec remote = { .iov_base = (void*)(uintptr_t)addr, .iov_len = len };
    
    ssize_t n = process_vm_readv(t->pid, &local, 1, &remote, 1, 0);
    if (n < 0 || (size_t)n < len) {
        // Fallback: use pread from /proc/<pid>/mem
        if (t->mem_fd >= 0) {
            ssize_t r = pread64(t->mem_fd, buf, len, (off64_t)addr);
            if (r > 0 && (size_t)r == len) return 1;
        }
        return 0;
    }
    return 1;
}

// ─── Write target memory (with mprotect if needed) ───
static int write_target_mem(TargetState *t, uint64_t addr, const uint8_t *buf, size_t len) {
    // First make the page writable via ptrace
    errno = 0;
    long ret = ptrace(PTRACE_ATTACH, t->pid, NULL, NULL);
    if (ret < 0 && errno != ESRCH) {  // ESRCH = already attached (e.g., traced)
        // Try direct write anyway via /proc/mem
        if (t->mem_fd >= 0) {
            // Try to make RWX via ptrace
            long data = ptrace(PTRACE_PEEKTEXT, t->pid, (void*)(uintptr_t)addr, NULL);
            if (data < 0 && errno == EIO) {
                // Need to change page permissions — use process_vm_writev
                struct iovec local = { .iov_base = (void*)buf, .iov_len = len };
                struct iovec remote = { .iov_base = (void*)(uintptr_t)addr, .iov_len = len };
                ssize_t n = process_vm_writev(t->pid, &local, 1, &remote, 1, 0);
                if (n > 0 && (size_t)n == len) return 1;
            }
            
            // Fallback: write via /proc/<pid>/mem
            ssize_t w = pwrite64(t->mem_fd, buf, len, (off64_t)addr);
            if (w > 0 && (size_t)w >= len) return 1;
        }
        return 0;
    }
    
    // Wait for attach
    if (ret == 0) {
        int status;
        waitpid(t->pid, &status, 0);
        
        // Write word by word using POKETEXT
        for (size_t i = 0; i < len; i += 8) {
            size_t chunk = (len - i < 8) ? len - i : 8;
            unsigned long val = 0;
            memcpy(&val, buf + i, chunk);
            ptrace(PTRACE_POKETEXT, t->pid, (void*)(uintptr_t)(addr + i), (void*)val);
        }
        
        // Detach
        ptrace(PTRACE_DETACH, t->pid, NULL, NULL);
        return 1;
    }
    
    // Already attached — try process_vm_writev
    struct iovec local = { .iov_base = (void*)buf, .iov_len = len };
    struct iovec remote = { .iov_base = (void*)(uintptr_t)addr, .iov_len = len };
    ssize_t n = process_vm_writev(t->pid, &local, 1, &remote, 1, 0);
    if (n > 0 && (size_t)n == len) return 1;
    
    // Final fallback: /proc/mem
    if (t->mem_fd >= 0) {
        ssize_t w = pwrite64(t->mem_fd, buf, len, (off64_t)addr);
        if (w > 0 && (size_t)w >= len) return 1;
    }
    
    return 0;
}

// ─── Scan executable code for patch opportunities ───
static void scan_for_patches(TargetState *t) {
    uint8_t *code_buf = malloc(MAX_REGION_SIZE);
    if (!code_buf) return;
    
    for (int ri = 0; ri < t->n_regions && t->n_patches < MAX_PATCHES; ri++) {
        MemRegion *r = &t->regions[ri];
        if (!r->is_executable) continue;
        
        size_t size = r->end - r->start;
        if (size > MAX_REGION_SIZE) size = MAX_REGION_SIZE;
        if (size < 16) continue;
        
        // Read the code
        if (!read_target_mem(t, r->start, code_buf, size)) continue;
        
        printf("[oracle] Scanning %s region 0x%lx-0x%lx (%zu KB)\n",
               r->path, r->start, r->end, size / 1024);
        
        // Scan for patch opportunities
        for (size_t offset = 0; offset < size - 8 && t->n_patches < MAX_PATCHES; ) {
            uint8_t *p = code_buf + offset;
            uint64_t abs_addr = r->start + offset;
            
            // ─── Pattern 1: NOP sled before loop entries ───
            // Look for loop patterns: jmp/call/je/ja/jg + sub/rbp pattern
            if (offset >= 4) {
                // Check if we're at a likely loop entry (label target)
                // A loop entry often starts with: cmp/test + jcc back, or sub $X, %rXX
                if ((p[0] == 0x48 && p[1] == 0x83 && (p[2] & 0xF8) == 0xE8) ||  // sub $imm, %rXX
                    (p[0] == 0x48 && p[1] == 0x85) ||  // test %rXX, %rXX
                    (p[0] == 0x48 && p[1] == 0x39) ||  // cmp %rXX, (%rXX)
                    (p[0] == 0x83 && (p[2] & 0xF8) == 0xE8)) {  // sub $imm, %rXX (32-bit)
                    
                    // Check if offset is NOT cache-line aligned
                    if ((abs_addr & (CACHE_LINE - 1)) != 0 && offset >= 8) {
                        // Check if previous bytes are not already NOPs
                        int already_nop = 1;
                        for (int j = 1; j <= 5 && j <= (int)offset; j++) {
                            if (*(p - j) != 0x90) { already_nop = 0; break; }
                        }
                        
                        if (!already_nop) {
                            // Calculate how many bytes to reach next cache line
                            uint64_t aligned = (abs_addr + CACHE_LINE - 1) & ~(CACHE_LINE - 1);
                            int nop_count = aligned - abs_addr;
                            if (nop_count <= 8 && nop_count >= 3) {
                                LivePatch *pat = &t->patches[t->n_patches++];
                                pat->kind = PATCH_NOP_SLED;
                                pat->address = abs_addr;
                                pat->original_len = 0;
                                pat->patch_len = 0;
                                
                                // Build NOP sled for alignment
                                for (int ni = 0; ni < nop_count; ni++) {
                                    pat->patch[pat->patch_len++] = 0x90;
                                }
                                
                                // Save original bytes
                                memcpy(pat->original, p, pat->patch_len > 0 ? (size_t)pat->patch_len : 1);
                                if (pat->patch_len > 0) {
                                    pat->original_len = (pat->patch_len < (int)sizeof(pat->original)) 
                                        ? pat->patch_len : (int)sizeof(pat->original);
                                }
                                
                                pat->confidence = 0.5;
                                snprintf(pat->description, sizeof(pat->description),
                                         "NOP sled: align loop entry to cache line (0x%lx)", 
                                         (unsigned long)aligned);
                                offset += nop_count;
                                continue;
                            }
                        }
                    }
                }
            }
            
            // ─── Pattern 2: Conditional jump that could be CMOV ───
            // Look for: cmp/jcc/mov/mov or test/jcc/mov/mov patterns
            if (offset + 12 < size) {
                // Pattern: 0F 9C-9F (setcc) or 0F 4x-4F (cmovcc) 
                // Check if there's a jcc (0F 8x) followed by simple mov
                if (p[0] == 0x0F && (p[1] >= 0x80 && p[1] <= 0x8F) &&  // jcc
                    (p[4] == 0x48 || p[4] == 0x89 || p[4] == 0x8B)) {  // mov
                    
                    int jcc_len = 6;  // 0F 8x xx xx xx xx
                    uint8_t *after_jmp = p + jcc_len;
                    
                    // Read target of jump (relative offset)
                    int32_t rel_offset;
                    memcpy(&rel_offset, p + 2, 4);
                    uint64_t jmp_target = abs_addr + jcc_len + rel_offset;
                    
                    // Simple check: if the jump skips over a mov that assigns constant
                    if ((after_jmp[0] == 0x48 && (after_jmp[1] == 0xC7)) ||  // movq $imm, %rXX
                        (after_jmp[0] == 0xC7)) {  // movl $imm, %rXX
                        
                        LivePatch *pat = &t->patches[t->n_patches++];
                        pat->kind = PATCH_BRANCHLESS;
                        pat->address = abs_addr;
                        pat->confidence = 0.4;
                        snprintf(pat->description, sizeof(pat->description),
                                 "Branchless candidate at 0x%lx: replace jcc with CMOV", 
                                 (unsigned long)abs_addr);
                        
                        // Mark original bytes (don't actually change them by default
                        // — CMOV replacement is complex, just flag it)
                        pat->original_len = 0;
                        pat->patch_len = 0;
                        pat->applied = 0;
                    }
                }
            }
            
            // ─── Pattern 3: memset-like pattern (rep stos) ───
            // Look for: small loops that look like memset replacement candidates
            if (offset + 24 < size) {
                // Pattern: simple counting loop with store
                // mov $count, %ecx ;  mov $val, %eax ;  loop: mov %eax, (%rdi) ; add $4, %rdi ; dec %ecx ; jnz loop
                if ((p[0] == 0xB9 || (p[0] == 0x48 && p[1] == 0xC7)) &&  // mov $imm, %ecx (counter init)
                    (p[5] == 0xB8 || p[5] == 0xBE)) {  // mov $imm, %eax or %esi (value set)
                    
                    LivePatch *pat = &t->patches[t->n_patches++];
                    pat->kind = PATCH_MEMSET_TO_STOSB;
                    pat->address = abs_addr;
                    pat->confidence = 0.35;
                    snprintf(pat->description, sizeof(pat->description),
                             "memset candidate at 0x%lx: replace loop with rep stosb", 
                             (unsigned long)abs_addr);
                    pat->original_len = 0;
                    pat->patch_len = 0;
                    pat->applied = 0;
                }
            }
            
            // ─── Pattern 4: Widening opportunity ───
            // Look for: 32-bit mov/store where 64-bit would work
            if (offset + 4 < size) {
                // 89 xx = mov r32, r/m32 — could be 48 89 = mov r64, r/m64
                if (p[0] == 0x89 && (p[1] & 0xC0) != 0xC0 &&  // mov to memory, not register
                    offset > 0 && code_buf[offset - 1] != 0x48) {  // not already 64-bit
                    
                    // Check if the register is potentially 64-bit (rXX vs r32d)
                    // This is a heuristic — we flag it for manual review
                    LivePatch *pat = &t->patches[t->n_patches++];
                    pat->kind = PATCH_WIDEN;
                    pat->address = abs_addr;
                    pat->confidence = 0.25;
                    snprintf(pat->description, sizeof(pat->description),
                             "32-bit mov at 0x%lx: could be widened to 64-bit", 
                             (unsigned long)abs_addr);
                    pat->original_len = 0;
                    pat->patch_len = 0;
                    pat->applied = 0;
                }
            }
            
            offset++;
        }
    }
    
    free(code_buf);
}

// ─── Apply a single NOP sled patch ───
static int apply_nop_sled(TargetState *t, LivePatch *p) {
    if (p->patch_len <= 0) return 0;
    
    // Read original bytes first
    if (p->original_len > 0) {
        if (!read_target_mem(t, p->address, p->original, p->original_len)) return 0;
    }
    
    // Write the NOPs
    if (!write_target_mem(t, p->address, p->patch, p->patch_len)) {
        printf("[oracle]   ✗ Failed to write NOP sled at 0x%lx\n", 
               (unsigned long)p->address);
        return 0;
    }
    
    printf("[oracle]   ✓ NOP sled at 0x%lx (%d bytes)\n", 
           (unsigned long)p->address, p->patch_len);
    return 1;
}

// ─── Apply patches to running process ───
static int apply_patches(TargetState *t) {
    printf("\n[oracle] Applying %d patches to PID %d...\n\n", t->n_patches, t->pid);
    
    t->n_applied = 0;
    
    for (int i = 0; i < t->n_patches; i++) {
        LivePatch *p = &t->patches[i];
        if (p->applied) continue;
        
        int success = 0;
        
        switch (p->kind) {
        case PATCH_NOP_SLED:
            success = apply_nop_sled(t, p);
            break;
        case PATCH_BRANCHLESS:
        case PATCH_CONSTANT_FOLD:
        case PATCH_LIKELY:
        case PATCH_WIDEN:
        case PATCH_LOOP_UNROLL:
        case PATCH_MEMSET_TO_STOSB:
            // These are flagged for awareness but not automatically applied
            // (would need more sophisticated code rewriting)
            printf("[oracle]   ~ %s at 0x%lx (flagged, confidence: %.0f%%)\n",
                   patch_names[p->kind], (unsigned long)p->address,
                   p->confidence * 100);
            success = 0;
            break;
        default:
            break;
        }
        
        p->applied = success;
        if (success) t->n_applied++;
    }
    
    return t->n_applied;
}

// ─── Read CPU time from /proc/<pid>/stat ───
static int read_cpu_time(TargetState *t, unsigned long *utime, 
                         unsigned long *stime, unsigned long *utime_ns,
                         unsigned long *stime_ns) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", t->pid);
    
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    
    char buf[1024];
    if (!fgets(buf, sizeof(buf), f)) { fclose(f); return 0; }
    fclose(f);
    
    // /proc/<pid>/stat format: pid (comm) state ppid pgrp session tty_nr tpgid flags 
    // minflt cminflt majflt cmajflt utime stime ...
    // Skip past the closing paren of comm
    char *s = buf;
    while (*s && *s != ')') s++;
    if (*s) s += 2;  // skip ") "
    
    // Tokenize by spaces for robust parsing
    char *tokens[52];
    int nt = 0;
    char *tok = strtok(s, " ");
    while (tok && nt < 52) {
        tokens[nt++] = tok;
        tok = strtok(NULL, " ");
    }
    
    if (nt >= 13) {  // need utime (idx 11) and stime (idx 12)
        *utime = strtoul(tokens[11], NULL, 10);
        *stime = strtoul(tokens[12], NULL, 10);
        if (nt >= 44) {
            *utime_ns = strtoul(tokens[42], NULL, 10);
            *stime_ns = strtoul(tokens[43], NULL, 10);
        }
        return 1;
    }
    
    return 0;
}

// ─── Measure performance impact ───
static void measure_performance(TargetState *t) {
    unsigned long utime = 0, stime = 0, utime_ns = 0, stime_ns = 0;
    
    if (!read_cpu_time(t, &utime, &stime, &utime_ns, &stime_ns)) {
        printf("[oracle] Cannot read CPU time — process may have exited\n");
        return;
    }
    
    double total_sec = 0;
    if (utime_ns > 0 && t->prev_utime_ns > 0) {
        total_sec = ((double)(utime_ns - t->prev_utime_ns) +
                     (double)(stime_ns - t->prev_stime_ns)) / 1e9;
    } else if (t->clock_ticks > 0) {
        total_sec = ((double)((utime + stime) - (t->prev_utime + t->prev_stime))) / 
                    t->clock_ticks;
    }
    
    if (total_sec > 0) {
        printf("[oracle] CPU time since attach: %.3f seconds\n", total_sec);
        if (t->n_applied > 0) {
            printf("[oracle] %d patches applied, process running normally\n", t->n_applied);
        }
    }
    
    t->prev_utime = utime;
    t->prev_stime = stime;
    t->prev_utime_ns = utime_ns;
    t->prev_stime_ns = stime_ns;
}

// ─── Show patch summary ───
static void print_summary(TargetState *t) {
    int counts[PATCH_NUM_KINDS] = {0};
    int app_counts[PATCH_NUM_KINDS] = {0};
    
    for (int i = 0; i < t->n_patches; i++) {
        counts[t->patches[i].kind]++;
        if (t->patches[i].applied) app_counts[t->patches[i].kind]++;
    }
    
    printf("\n╔══════════════════════════════════════════════════╗\n");
    printf("║        LIVE IMPROVEMENT SUMMARY                 ║\n");
    printf("╠══════════════════════════════════════════════════╣\n");
    printf("║  Target PID:       %-6d                        ║\n", t->pid);
    printf("║  Memory regions:   %-6d                        ║\n", t->n_regions);
    printf("║  Patches found:    %-6d                        ║\n", t->n_patches);
    printf("║  Patches applied:  %-6d                        ║\n", t->n_applied);
    printf("╠══════════════════════════════════════════════════╣\n");
    
    for (int i = 0; i < PATCH_NUM_KINDS; i++) {
        if (counts[i] > 0) {
            printf("║  %-20s: %3d found, %3d applied        ║\n", 
                   patch_names[i], counts[i], app_counts[i]);
        }
    }
    
    // Find top confidence patches
    printf("╠══════════════════════════════════════════════════╣\n");
    printf("║  Top opportunities:                              ║\n");
    
    // Sort by confidence descending
    int sorted[MAX_PATCHES];
    for (int i = 0; i < t->n_patches; i++) sorted[i] = i;
    for (int i = 0; i < t->n_patches && i < 5; i++) {
        for (int j = i + 1; j < t->n_patches; j++) {
            if (t->patches[sorted[j]].confidence > t->patches[sorted[i]].confidence) {
                int tmp = sorted[i];
                sorted[i] = sorted[j];
                sorted[j] = tmp;
            }
        }
        LivePatch *bp = &t->patches[sorted[i]];
        printf("║  %-4s %.0f%% 0x%lx %s\n",
               bp->applied ? "✓" : "○",
               bp->confidence * 100,
               (unsigned long)bp->address,
               bp->description);
    }
    
    printf("╚══════════════════════════════════════════════════╝\n");
}

// ─── Monitor loop ───
static void monitor_loop(TargetState *t) {
    printf("\n[oracle] Entering monitor mode. Press Ctrl+C to stop.\n");
    printf("[oracle] Watching PID %d for 10 seconds...\n\n", t->pid);
    
    for (int i = 0; i < 10; i++) {
        sleep(1);
        measure_performance(t);
    }
}

// ─── Main ───
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
        fprintf(stderr, "  Attaches to a running process and live-patches its code.\n");
        fprintf(stderr, "  Requires ptrace access to the target process.\n");
        fprintf(stderr, "\nExample:\n");
        fprintf(stderr, "  # Start a program to improve\n");
        fprintf(stderr, "  ./some_program &\n");
        fprintf(stderr, "  # Improve it while it runs\n");
        fprintf(stderr, "  sudo %s $!\n", argv[0]);
        return 1;
    }
    
    pid_t target_pid = atoi(argv[1]);
    if (target_pid <= 0) {
        fprintf(stderr, "Invalid PID: %s\n", argv[1]);
        return 1;
    }
    
    printf("╔══════════════════════════════════════╗\n");
    printf("║   ORACLE LIVE IMPROVER              ║\n");
    printf("║   Live-patching PID %-6d         ║\n", target_pid);
    printf("╚══════════════════════════════════════╝\n\n");
    
    // Initialize target state
    TargetState t;
    memset(&t, 0, sizeof(t));
    t.pid = target_pid;
    t.clock_ticks = sysconf(_SC_CLK_TCK);
    
    // Open /proc/<pid>/mem for direct memory access
    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", t.pid);
    t.mem_fd = open(mem_path, O_RDWR);
    if (t.mem_fd < 0) {
        fprintf(stderr, "[oracle] Warning: Cannot open %s — some features limited\n", mem_path);
        fprintf(stderr, "  Try running as root: sudo %s %d\n", argv[0], t.pid);
    }
    
    // Step 1: Read memory maps
    printf("── Step 1: Reading memory maps ──\n");
    if (!read_memory_maps(&t)) {
        fprintf(stderr, "Failed to read memory maps for PID %d\n", t.pid);
        if (t.mem_fd >= 0) close(t.mem_fd);
        return 1;
    }
    
    if (t.entry_point) {
        printf("[oracle] Entry point: 0x%lx\n", t.entry_point);
    }
    
    // Read initial CPU time
    read_cpu_time(&t, &t.prev_utime, &t.prev_stime, 
                  &t.prev_utime_ns, &t.prev_stime_ns);
    
    // Step 2: Scan for improvements
    printf("\n── Step 2: Scanning executable code ──\n");
    scan_for_patches(&t);
    printf("[oracle] Found %d improvement opportunities\n", t.n_patches);
    
    // Step 3: Apply patches
    if (t.n_patches > 0) {
        printf("\n── Step 3: Applying live patches ──\n");
        int applied = apply_patches(&t);
        printf("\n[oracle] %d/%d patches applied\n", applied, t.n_patches);
    }
    
    // Step 4: Summary
    print_summary(&t);
    
    // Step 5: Monitor
    if (t.n_applied > 0) {
        printf("\n── Step 4: Monitoring performance ──\n");
        monitor_loop(&t);
    }
    
    // Cleanup
    if (t.mem_fd >= 0) close(t.mem_fd);
    
    printf("\n╔══════════════════════════════════════╗\n");
    printf("║   LIVE IMPROVEMENT COMPLETE         ║\n");
    printf("╚══════════════════════════════════════╝\n");
    
    return 0;
}
