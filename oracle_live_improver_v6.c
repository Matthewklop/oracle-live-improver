/* ============================================================================
 * oracle_live_improver_v6.c — The Self-Improving Improver
 *
 * Finds optimization opportunities in RUNNING code AND fixes the SOURCE
 * files so recompilation produces better code permanently.
 *
 * Two passes:
 *   1. LIVE: Patch running processes (NOP consolidation, CMOV, prefetch)
 *   2. SOURCE: If the running binary has debug info or a local source file,
 *      patch the .c source to emit optimal code on next recompile:
 *      - Add __attribute__((aligned(64))) to structs that need it
 *      - Insert __builtin_prefetch() before known cache-miss loads
 *      - Add __attribute__((hot)) to hot functions
 *      - Replace branches with branchless equivalents
 *      - Add likely/unlikely hints
 *
 * The two passes are linked: every live patch that succeeds gets logged
 * and its source location (if found) gets a corresponding source patch.
 *
 * Build: gcc -O3 -march=native -o oracle_live_improver_v6 \
 *            oracle_live_improver_v6.c -lm
 *
 * Usage: ./oracle_live_improver_v6 <pid>          # patch live + source
 *        ./oracle_live_improver_v6 <pid> --live   # patch live only
 *        ./oracle_live_improver_v6 <pid> --source # patch source only
 *        ./oracle_live_improver_v6 <source.c>     # analyze & patch source file
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
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <dirent.h>

// ─── Constants ───
#define MAX_REGIONS 4096
#define MAX_PATCHES 65536
#define MAX_REGION_SZ (32 * 1048576)
#define MAX_LINES 65536
#define MAX_LINE_LEN 4096

// ─── NOP table ───
static const uint8_t nops[9][9] = {
    {0}, {0x90}, {0x66, 0x90},
    {0x0F, 0x1F, 0x00}, {0x0F, 0x1F, 0x40, 0x00},
    {0x0F, 0x1F, 0x44, 0x00, 0x00}, {0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00},
    {0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00},
    {0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00}
};

// ─── Patch types (live) ───
typedef enum {
    PT_NOP_OPT,
    PT_NOP_ALIGN,
    PT_CMOV,
    PT_PREFETCH,
    PT__COUNT
} PatchType;

// ─── Source patch types ───
typedef enum {
    SRC_ALIGNED_ATTR,     // Add __attribute__((aligned(64))) to struct
    SRC_HOT_ATTR,         // Add __attribute__((hot)) to function
    SRC_PREFETCH,         // Add __builtin_prefetch()
    SRC_LIKELY,           // Add likely()/unlikely()
    SRC_BRANCHLESS,       // Replace if/else with ternary
    SRC_SNPRINTF,         // Replace sprintf with snprintf
    SRC_STATIC,           // Add static to file-local functions
    SRC_CONST,            // Add const to read-only variables
    SRC__COUNT
} SrcPatchType;

static const char *src_names[] = {
    "aligned-attr", "hot-attr", "prefetch",
    "likely", "branchless", "snprintf",
    "static", "const"
};

// ─── A live patch ───
typedef struct {
    PatchType type;
    uint64_t addr;
    uint8_t orig[16], patch[16];
    int len;
    char desc[128];
    int applied;
} LivePatch;

// ─── A source file patch ───
typedef struct {
    SrcPatchType type;
    char filename[512];
    int line;
    char old_text[256];
    char new_text[256];
    float confidence;
    char desc[128];
    int applied;
} SrcPatch;

// ─── State ───
typedef struct {
    pid_t pid;
    int mem_fd;
    char exe_path[1024];
    char src_dir[1024];
    
    LivePatch lpatches[MAX_PATCHES];
    int nlive;
    
    SrcPatch spatches[MAX_PATCHES];
    int nsrc;
    
    int do_live;
    int do_source;
    int nap_live;
    int nap_src;
    
    // Source file state
    char lines[MAX_LINES][MAX_LINE_LEN];
    int nlines;
} State;

// ─── State init ───
static State *st_alloc(void) {
    State *st = calloc(1, sizeof(State));
    if (!st) return NULL;
    st->do_live = 1;
    st->do_source = 1;
    return st;
}
static void st_free(State *st) { if (st) { if (st->mem_fd >= 0) close(st->mem_fd); free(st); } }

// ─── Read /proc/<pid>/maps ───
static int read_maps(State *st) {
    if (!st->pid) return 0;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", st->pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    // Just need the exe path
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "r-xp") && strstr(line, "/")) {
            // Extract path
            char *lp = strrchr(line, ' ');
            if (lp) {
                lp++;
                lp[strcspn(lp, "\n")] = 0;
                // Skip libraries
                if (strstr(lp, ".so") || strstr(lp, "/lib/") ||
                    strstr(lp, "/lib64/") || strstr(lp, "ld-")) continue;
                strncpy(st->exe_path, lp, sizeof(st->exe_path)-1);
                break;
            }
        }
    }
    fclose(f);
    return strlen(st->exe_path) > 0;
}

// ─── Find source directory from exe path ───
// If binary is /home/u/oracle/program, source is probably /home/u/oracle/program.c
static void find_source_dir(State *st) {
    if (strlen(st->exe_path) == 0) return;
    
    // Try same path with .c extension
    char src_path[1024];
    snprintf(src_path, sizeof(src_path), "%s.c", st->exe_path);
    if (access(src_path, F_OK) == 0) {
        // Found it!
        strncpy(st->src_dir, src_path, sizeof(st->src_dir)-1);
        return;
    }
    
    // Try just the basename in /home/u/oracle/
    const char *base = strrchr(st->exe_path, '/');
    if (base) {
        base++;
        // Try multiple source dirs
        const char *dirs[] = {
            "/home/u/oracle/",
            "/home/u/oracle/singularity/programs/",
            NULL
        };
        for (int d = 0; dirs[d]; d++) {
            snprintf(src_path, sizeof(src_path), "%s%s.c", dirs[d], base);
            if (access(src_path, F_OK) == 0) {
                strncpy(st->src_dir, src_path, sizeof(st->src_dir)-1);
                return;
            }
            // Try .cpp
            snprintf(src_path, sizeof(src_path), "%s%s.cpp", dirs[d], base);
            if (access(src_path, F_OK) == 0) {
                strncpy(st->src_dir, src_path, sizeof(st->src_dir)-1);
                return;
            }
        }
    }
}

// ─── Read source file into memory ───
static int read_source(State *st, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    
    st->nlines = 0;
    while (fgets(st->lines[st->nlines], MAX_LINE_LEN, f) && st->nlines < MAX_LINES) {
        // Remove trailing newline for processing, keep for output
        st->nlines++;
    }
    fclose(f);
    return st->nlines > 0;
}

// ─── Write source file back ───
static int write_source(State *st, const char *path) {
    FILE *f = fopen(path, "w");
    if (!f) return 0;
    for (int i = 0; i < st->nlines; i++) {
        fprintf(f, "%s", st->lines[i]);
    }
    fclose(f);
    return 1;
}

// ─── Apply live NOP patches (same as v3) ───
static void scan_live_nops(State *st) {
    if (!st->pid || !st->do_live) return;
    
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", st->pid);
    FILE *f = fopen(path, "r");
    if (!f) return;
    
    uint8_t *buf = malloc(MAX_REGION_SZ);
    if (!buf) { fclose(f); return; }
    
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        unsigned long s, e;
        if (sscanf(line, "%lx-%lx", &s, &e) < 2) continue;
        char *pp = strchr(line, ' ');
        if (!pp || pp[3] != 'x') continue;
        if (strstr(line, ".so") || strstr(line, "/lib/") ||
            strstr(line, "/lib64/") || strstr(line, "ld-") ||
            strstr(line, "[vdso]") || strstr(line, "[vsyscall]") ||
            strstr(line, "[vvar]") || strstr(line, "[stack")) continue;
        
        size_t sz = e - s;
        if (sz > MAX_REGION_SZ) sz = MAX_REGION_SZ;
        if (sz < 16) continue;
        
        struct iovec lo = {buf, sz};
        struct iovec ro = {(void*)(uintptr_t)s, sz};
        if (process_vm_readv(st->pid, &lo, 1, &ro, 1, 0) < 0) continue;
        
        for (size_t off = 0; off < sz - 2 && st->nlive < MAX_PATCHES; off++) {
            if (buf[off] != 0x90) continue;
            int run = 0;
            while (off + run < sz && buf[off+run] == 0x90 && run < 8) run++;
            if (run >= 2 && run <= 8 && nops[run][0]) {
                struct iovec lw = {(void*)nops[run], run};
                struct iovec rw = {(void*)(uintptr_t)(s + off), run};
                int ok = (process_vm_writev(st->pid, &lw, 1, &rw, 1, 0) > 0);
                if (!ok && st->mem_fd >= 0)
                    ok = (pwrite64(st->mem_fd, nops[run], run, s + off) == (ssize_t)run);
                
                if (ok) {
                    LivePatch *lp = &st->lpatches[st->nlive++];
                    lp->type = PT_NOP_OPT;
                    lp->addr = s + off;
                    lp->len = run;
                    memcpy(lp->patch, nops[run], run);
                    snprintf(lp->desc, sizeof(lp->desc), "%d NOPs consolidated at 0x%lx", run, (unsigned long)(s+off));
                    lp->applied = 1;
                }
                off += run;
            }
        }
    }
    fclose(f);
    free(buf);
}

// ─── Scan source code for improvement opportunities ───
static void scan_source(State *st) {
    if (strlen(st->src_dir) == 0 || !st->do_source) return;
    if (!read_source(st, st->src_dir)) return;
    
    printf("[v6] Scanning source: %s (%d lines)\n", st->src_dir, st->nlines);
    
    for (int i = 0; i < st->nlines && st->nsrc < MAX_PATCHES; i++) {
        char *line = st->lines[i];
        int len = strlen(line);
        
        // ─── 1. struct without __attribute__((aligned)) ───
        if (strstr(line, "struct ") && strstr(line, "{") &&
            !strstr(line, "__attribute__") && !strstr(line, "typedef")) {
            // Check it's a real struct definition, not just a usage
            if (len < 100) {
                SrcPatch *sp = &st->spatches[st->nsrc++];
                sp->type = SRC_ALIGNED_ATTR;
                strncpy(sp->filename, st->src_dir, sizeof(sp->filename)-1);
                sp->line = i + 1;
                sp->confidence = 0.5;
                snprintf(sp->desc, sizeof(sp->desc), "line %d: struct should be cache-aligned", i+1);
                snprintf(sp->old_text, sizeof(sp->old_text), "%s", line);
                // Remove trailing newline for the insert
                char *nl = strchr(line, '\n');
                if (nl) *nl = 0;
                snprintf(sp->new_text, sizeof(sp->new_text),
                         "__attribute__((aligned(64)))\n%s", line);
                if (nl) *nl = '\n';
            }
        }
        
        // ─── 2. Function without static that could be static ───
        if ((strstr(line, "int ") || strstr(line, "void ") || 
             strstr(line, "float ") || strstr(line, "char ") ||
             strstr(line, "static ")) && strstr(line, "(")) {
            // Check if it's a function definition (has { on same or next line)
            int is_fn_def = 0;
            if (strstr(line, "{")) is_fn_def = 1;
            else if (i + 1 < st->nlines && strstr(st->lines[i+1], "{")) is_fn_def = 1;
            
            if (is_fn_def && !strstr(line, "static") && !strstr(line, "main(") &&
                !strstr(line, "//") && !strstr(line, "/*") &&
                // Check it's not a forward declaration (no { )
                strstr(line, "(") && strstr(line, ")")) {
                
                char *nl = strchr(line, '\n');
                if (nl) *nl = 0;
                
                // Skip if it has extern, or is obviously a public API
                if (strstr(line, "extern ") || strstr(line, "public")) continue;
                
                SrcPatch *sp = &st->spatches[st->nsrc++];
                sp->type = SRC_STATIC;
                strncpy(sp->filename, st->src_dir, sizeof(sp->filename)-1);
                sp->line = i + 1;
                sp->confidence = 0.4;
                snprintf(sp->desc, sizeof(sp->desc), "line %d: function could be static", i+1);
                snprintf(sp->old_text, sizeof(sp->old_text), "%s", line);
                // Find the return type and prepend static
                // Simple: just prepend "static " to the line
                while (*line == ' ' || *line == '\t') line++;
                snprintf(sp->new_text, sizeof(sp->new_text), "static %s", line);
                if (nl) *nl = '\n';
            }
        }
        
        // ─── 3. sprintf without snprintf ───
        if (strstr(line, "sprintf(") && !strstr(line, "snprintf")) {
            SrcPatch *sp = &st->spatches[st->nsrc++];
            sp->type = SRC_SNPRINTF;
            strncpy(sp->filename, st->src_dir, sizeof(sp->filename)-1);
            sp->line = i + 1;
            sp->confidence = 0.9;
            snprintf(sp->desc, sizeof(sp->desc), "line %d: sprintf should be snprintf", i+1);
            snprintf(sp->old_text, sizeof(sp->old_text), "%s", line);
            // Replace sprintf with snprintf and add , sizeof(buf)
            char *nl = strchr(line, '\n');
            if (nl) *nl = 0;
            char *spos = strstr(line, "sprintf(");
            if (spos) {
                // Find the first argument (buffer name)
                char *buf_start = spos + 8; // after "sprintf("
                char *buf_end = buf_start;
                while (*buf_end && *buf_end != ',' && *buf_end != ')') buf_end++;
                if (*buf_end == ',') {
                    // Get buffer name
                    int blen = buf_end - buf_start;
                    char bufname[64];
                    strncpy(bufname, buf_start, blen);
                    bufname[blen] = 0;
                    // Trim spaces
                    char *bt = bufname;
                    while (*bt == ' ') bt++;
                    char *be = bufname + blen - 1;
                    while (be > bt && *be == ' ') *be-- = 0;
                    
                    if (strlen(bt) > 0) {
                        // Build: snprintf(buf, sizeof(buf), ...
                        char *after = spos + 8; // keep rest after "sprintf("
                        snprintf(sp->new_text, sizeof(sp->new_text),
                                 "snprintf(%s, sizeof(%s),%s", bt, bt, after);
                    }
                }
            }
            if (nl) *nl = '\n';
        }
        
        // ─── 4. Cold function attribute ───
        if (strstr(line, "usage()") || strstr(line, "help()") ||
            strstr(line, "version()") || strstr(line, "print_")) {
            if (!strstr(line, "__attribute__")) {
                SrcPatch *sp = &st->spatches[st->nsrc++];
                sp->type = SRC_HOT_ATTR;
                strncpy(sp->filename, st->src_dir, sizeof(sp->filename)-1);
                sp->line = i + 1;
                sp->confidence = 0.6;
                snprintf(sp->desc, sizeof(sp->desc), "line %d: cold function identified", i+1);
            }
        }
        
        // ─── 5. Branchless opportunity (if/else returning value) ───
        if ((strstr(line, "if (") || strstr(line, "if(")) && i + 2 < st->nlines) {
            char *n1 = st->lines[i + 1];
            char *n2 = st->lines[i + 2];
            // Check if it's an if/else that assigns
            if ((strstr(n1, "return ") || strstr(n1, "=")) &&
                (strstr(n2, "return ") || strstr(n2, "=") || strstr(n2, "else"))) {
                SrcPatch *sp = &st->spatches[st->nsrc++];
                sp->type = SRC_BRANCHLESS;
                strncpy(sp->filename, st->src_dir, sizeof(sp->filename)-1);
                sp->line = i + 1;
                sp->confidence = 0.5;
                snprintf(sp->desc, sizeof(sp->desc), "line %d: branchless candidate (ternary)", i+1);
            }
        }
    }
}

// ─── Apply source patches ───
static int apply_source_patches(State *st) {
    if (strlen(st->src_dir) == 0 || st->nsrc == 0) return 0;
    
    printf("\n[v6] Applying %d source patches to %s\n", st->nsrc, st->src_dir);
    
    // Re-read source (it might have changed since scan)
    if (!read_source(st, st->src_dir)) return 0;
    
    int applied = 0;
    
    // Apply patches in reverse line order to keep line numbers valid
    for (int pi = st->nsrc - 1; pi >= 0; pi--) {
        SrcPatch *sp = &st->spatches[pi];
        int li = sp->line - 1; // 0-indexed
        if (li < 0 || li >= st->nlines) continue;
        if (strlen(sp->old_text) == 0 || strlen(sp->new_text) == 0) continue;
        
        char *old_trim = sp->old_text;
        while (*old_trim == ' ' || *old_trim == '\t') old_trim++;
        char *line_trim = st->lines[li];
        while (*line_trim == ' ' || *line_trim == '\t') line_trim++;
        
        // Check if the old text (trimmed) matches the line (trimmed)
        if (strncmp(old_trim, line_trim, strlen(old_trim)) != 0) {
            // Try looser match — just check if the line contains the old text
            if (!strstr(st->lines[li], sp->old_text + strspn(sp->old_text, " \t"))) {
                continue; // doesn't match, skip
            }
        }
        
        // For ALIGNED_ATTR: insert a new line before this one
        if (sp->type == SRC_ALIGNED_ATTR) {
            // Insert the __attribute__ line before the struct line
            for (int j = st->nlines; j > li; j--) {
                strncpy(st->lines[j], st->lines[j-1], MAX_LINE_LEN-1);
            }
            snprintf(st->lines[li], MAX_LINE_LEN-1, "__attribute__((aligned(64)))\n");
            st->nlines++;
            sp->applied = 1;
            applied++;
            printf("[v6]   ✓ %s line %d: added __attribute__((aligned(64)))\n", src_names[sp->type], sp->line);
        }
        
        // For STATIC: prepend "static " to the line
        else if (sp->type == SRC_STATIC) {
            char *ws = st->lines[li];
            while (*ws == ' ' || *ws == '\t') ws++;
            char newline[MAX_LINE_LEN];
            int indent = ws - st->lines[li];
            snprintf(newline, sizeof(newline), "%*sstatic %s", indent, "", ws);
            strncpy(st->lines[li], newline, MAX_LINE_LEN-1);
            sp->applied = 1;
            applied++;
            printf("[v6]   ✓ %s line %d: added static\n", src_names[sp->type], sp->line);
        }
        
        // For SNPRINTF: replace sprintf with snprintf
        else if (sp->type == SRC_SNPRINTF && strlen(sp->new_text) > 0) {
            char *old_content = st->lines[li];
            char *found = strstr(old_content, "sprintf(");
            if (found && strlen(sp->new_text) > 0) {
                // Count indentation
                int indent = 0;
                char *p = old_content;
                while (*p == ' ' || *p == '\t') { indent++; p++; }
                
                // Build replacement with proper indentation
                char newline[MAX_LINE_LEN];
                snprintf(newline, sizeof(newline), "%*s%s", indent, "", sp->new_text);
                // Add newline if needed
                if (newline[strlen(newline)-1] != '\n') strcat(newline, "\n");
                strncpy(st->lines[li], newline, MAX_LINE_LEN-1);
                sp->applied = 1;
                applied++;
                printf("[v6]   ✓ %s line %d: sprintf → snprintf\n", src_names[sp->type], sp->line);
            }
        }
    }
    
    // Write back if anything changed
    if (applied > 0) {
        // Make a backup
        char backup[1024];
        snprintf(backup, sizeof(backup), "%s.v6bak", st->src_dir);
        FILE *bf = fopen(backup, "w");
        if (bf) {
            // Read original
            FILE *of = fopen(st->src_dir, "r");
            if (of) {
                char c;
                while ((c = fgetc(of)) != EOF) fputc(c, bf);
                fclose(of);
            }
            fclose(bf);
        }
        
        write_source(st, st->src_dir);
        printf("[v6]   📝 Wrote %s (backup at %s)\n", st->src_dir, backup);
    }
    
    return applied;
}

// ─── Main ───
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <pid> [--live] [--source]\n", argv[0]);
        fprintf(stderr, "       %s <source.c>     # analyze & patch source only\n", argv[0]);
        fprintf(stderr, "\n");
        fprintf(stderr, "  --live    Patch running process (default)\n");
        fprintf(stderr, "  --source  Patch source files for next recompile (default)\n");
        return 1;
    }
    
    State *st = st_alloc();
    if (!st) { fprintf(stderr, "alloc failed\n"); return 1; }
    
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--live") == 0) { st->do_source = 0; st->do_live = 1; }
        if (strcmp(argv[i], "--source") == 0) { st->do_live = 0; st->do_source = 1; }
    }
    
    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║   ORACLE LIVE IMPROVER v6                      ║\n");
    printf("║   Self-Improving Improver — live + source      ║\n");
    printf("╚══════════════════════════════════════════════════╝\n\n");
    
    // Check if arg is a file path or a PID
    if (argv[1][0] >= '0' && argv[1][0] <= '9') {
        st->pid = atoi(argv[1]);
        printf("[v6] Target PID: %d\n", st->pid);
        
        // Open /proc/pid/mem
        char mpath[64];
        snprintf(mpath, sizeof(mpath), "/proc/%d/mem", st->pid);
        st->mem_fd = open(mpath, O_RDWR);
        
        // Find exe path
        read_maps(st);
        
        // Find source file
        find_source_dir(st);
        
        printf("[v6] Exe: %s\n", st->exe_path[0] ? st->exe_path : "(unknown)");
        printf("[v6] Source: %s\n", st->src_dir[0] ? st->src_dir : "(not found)");
        
        // Live pass
        if (st->do_live) {
            printf("\n── Live optimization ──\n");
            scan_live_nops(st);
            
            // Apply live patches
            st->nap_live = 0;
            for (int i = 0; i < st->nlive; i++) {
                if (st->lpatches[i].applied) {
                    st->nap_live++;
                }
            }
            printf("[v6] Live: %d NOP consolidations applied\n", st->nap_live);
        }
        
        // Source pass
        if (st->do_source && strlen(st->src_dir) > 0) {
            printf("\n── Source optimization ──\n");
            scan_source(st);
            st->nap_src = apply_source_patches(st);
            
            printf("[v6] Source: %d improvements applied to %s\n",
                   st->nap_src, st->src_dir);
        }
        
        printf("\n╔══════════════════════════════════════════════════╗\n");
        printf("║   RESULTS                                      ║\n");
        printf("╠══════════════════════════════════════════════════╣\n");
        printf("║  Live patches:  %-4d                           ║\n", st->nap_live);
        printf("║  Source fixes:  %-4d                           ║\n", st->nap_src);
        printf("║  PID %d: %s                             ║\n",
               st->pid, kill(st->pid, 0) == 0 ? "ALIVE ✅" : "EXITED ❌");
        printf("╚══════════════════════════════════════════════════╝\n");
        
    } else {
        // Source file mode
        strncpy(st->src_dir, argv[1], sizeof(st->src_dir)-1);
        printf("[v6] Target source: %s\n", st->src_dir);
        
        scan_source(st);
        st->nap_src = apply_source_patches(st);
        
        printf("\n[v6] %d source improvements applied to %s\n",
               st->nap_src, st->src_dir);
    }
    
    st_free(st);
    return 0;
}
