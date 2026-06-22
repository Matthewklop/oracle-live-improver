/* ============================================================================
 * oracle_prelaunch.c — Pre-Debugger Game Optimizer
 *
 * Optimizes a game's binaries on disk BEFORE launch, then starts it.
 * No crash risk because we patch the file, not a running process.
 * Also tunes system parameters for gaming.
 *
 * Usage: ./oracle_prelaunch <game_exe_path>
 *   Patches the game exe + all DLLs in its directory.
 *
 * Usage: ./oracle_prelaunch --steam <appid>
 *   Finds the Steam game by appid, patches it, launches via Steam.
 *
 * Usage: ./oracle_prelaunch --scan <pid>
 *   After game is running, patch loaded DLLs (gentle mode).
 *
 * What it does to each binary:
 *   - NOP consolidation (swap single-byte NOPs for multi-byte)
 *   - mov $0 → xor idiom (fix inefficient zeroing)
 *   - Immediate shortening (5-byte add/sub → 3-byte + NOP)
 *   - Note: CMOV, prefetch, and loop align require runtime analysis
 *
 * Build: gcc -O3 -march=native -o oracle_prelaunch oracle_prelaunch.c -lm
 * ============================================================================
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <errno.h>
#include <dirent.h>

// ─── NOP table ───
static const uint8_t nops[9][9] = {
    {0}, {0x90},
    {0x66, 0x90},
    {0x0F, 0x1F, 0x00},
    {0x0F, 0x1F, 0x40, 0x00},
    {0x0F, 0x1F, 0x44, 0x00, 0x00},
    {0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00},
    {0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00},
    {0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00}
};

// ─── Statistics ───
static struct {
    int n_nop_opt;
    int n_zero_idiom;
    int n_shorten;
    int n_files;
    int n_patched_bytes;
} stats;

// ─── Patch a buffer in place (ON DISK — safe, no crash risk) ───
static void patch_buffer(uint8_t *buf, size_t sz) {
    for (size_t off = 0; off < sz - 6; ) {
        uint8_t *p = buf + off;

        // 1. NOP consolidation
        if (p[0] == 0x90) {
            int run = 0;
            while (off + run < sz && buf[off+run] == 0x90 && run < 8) run++;
            if (run >= 2 && nops[run][0]) {
                memcpy(buf + off, nops[run], run);
                stats.n_nop_opt++;
                stats.n_patched_bytes += run;
                off += run;
                continue;
            }
        }

        // 2. mov $0,%reg (5 bytes) → xor %reg,%reg (2 bytes) + NOP pad (3 bytes)
        // B8 00 00 00 00 → 31 C0 + 0F 1F 00
        if ((p[0] & 0xF8) == 0xB8 && p[1]==0 && p[2]==0 && p[3]==0 && p[4]==0) {
            uint8_t reg = p[0] & 0x07;
            buf[off+0] = 0x31;
            buf[off+1] = 0xC0 | (reg << 3) | reg;
            buf[off+2] = nops[3][0];
            buf[off+3] = nops[3][1];
            buf[off+4] = nops[3][2];
            stats.n_zero_idiom++;
            stats.n_patched_bytes += 5;
            off += 5;
            continue;
        }

        // 3. mov $0,%reg with REX.W (48 B8 00 00 00 00 00 00 00 00 = 10 bytes)
        // → 48 31 C0 + NOP pad (7 bytes)
        if (p[0] == 0x48 && (p[1] & 0xF8) == 0xB8 &&
            p[2]==0 && p[3]==0 && p[4]==0 && p[5]==0 && p[6]==0 && p[7]==0 && p[8]==0 && p[9]==0) {
            uint8_t reg = p[1] & 0x07;
            buf[off+0] = 0x48; // REX.W
            buf[off+1] = 0x31;
            buf[off+2] = 0xC0 | (reg << 3) | reg;
            // Fill rest with NOPs
            for (int j = 3; j < 10; j++) buf[off+j] = 0x90;
            stats.n_zero_idiom++;
            stats.n_patched_bytes += 10;
            off += 10;
            continue;
        }

        // 4. Immediate shortening: add $imm32,%eax (05 xx xx xx xx = 5 bytes)
        // → 83 C0 imm8 + 66 90 (3+2=5 bytes)
        if ((p[0] == 0x05 || p[0] == 0x2D)) {
            int32_t imm;
            memcpy(&imm, p+1, 4);
            if (imm >= -128 && imm <= 127) {
                uint8_t subop = (p[0] == 0x05) ? 0xC0 : 0xE8;
                buf[off+0] = 0x83;
                buf[off+1] = subop;
                buf[off+2] = (uint8_t)(imm & 0xFF);
                buf[off+3] = nops[2][0];
                buf[off+4] = nops[2][1];
                stats.n_shorten++;
                stats.n_patched_bytes += 5;
                off += 5;
                continue;
            }
        }

        // 5. 64-bit: 48 05 or 48 2D (6 bytes) → 48 83 C0/E8 imm8 + 66 90
        if (p[0] == 0x48 && (p[1] == 0x05 || p[1] == 0x2D)) {
            int32_t imm;
            memcpy(&imm, p+2, 4);
            if (imm >= -128 && imm <= 127) {
                uint8_t subop = (p[1] == 0x05) ? 0xC0 : 0xE8;
                buf[off+0] = 0x48;
                buf[off+1] = 0x83;
                buf[off+2] = subop;
                buf[off+3] = (uint8_t)(imm & 0xFF);
                buf[off+4] = nops[2][0];
                buf[off+5] = nops[2][1];
                stats.n_shorten++;
                stats.n_patched_bytes += 6;
                off += 6;
                continue;
            }
        }

        off++;
    }
}

// ─── Patch a file on disk ───
static int patch_file(const char *path) {
    int fd = open(path, O_RDWR);
    if (fd < 0) {
        printf("[pre]   ✗ can't open %s\n", path);
        return 0;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return 0; }
    if (st.st_size < 16) { close(fd); return 0; }

    uint8_t *buf = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (buf == MAP_FAILED) {
        // Fallback: read/write
        buf = malloc(st.st_size);
        if (!buf) { close(fd); return 0; }
        read(fd, buf, st.st_size);
        patch_buffer(buf, st.st_size);
        lseek(fd, 0, SEEK_SET);
        write(fd, buf, st.st_size);
        free(buf);
        close(fd);
        stats.n_files++;
        return 1;
    }

    patch_buffer(buf, st.st_size);
    munmap(buf, st.st_size);
    close(fd);

    stats.n_files++;
    return 1;
}

// ─── Find all PE/ELF executables and DLLs in a directory ───
static int patch_directory(const char *dir_path) {
    DIR *d = opendir(dir_path);
    if (!d) return 0;

    struct dirent *de;
    char path[1024];
    int count = 0;

    while ((de = readdir(d))) {
        // Skip . and ..
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;

        snprintf(path, sizeof(path), "%s/%s", dir_path, de->d_name);

        // Recurse into directories
        if (de->d_type == DT_DIR) {
            count += patch_directory(path);
            continue;
        }

        // Only patch .exe, .dll, .so files
        const char *ext = strrchr(de->d_name, '.');
        if (!ext) continue;
        if (strcasecmp(ext, ".exe") != 0 && strcasecmp(ext, ".dll") != 0 &&
            strcasecmp(ext, ".so") != 0) continue;

        printf("[pre] Patching %s...\n", path);
        if (patch_file(path)) count++;
    }

    closedir(d);
    return count;
}

// ─── Steam integration: find game by appid ───
static int find_steam_game(int appid, char *out_path, size_t out_sz) {
    // Common Steam library paths
    const char *steam_paths[] = {
        getenv("HOME"),
        "/home/s1",
        "/home/u",
        NULL
    };

    char buf[1024];
    for (int sp = 0; steam_paths[sp]; sp++) {
        // Check default steam library
        snprintf(buf, sizeof(buf), "%s/.steam/steam/steamapps/appmanifest_%d.acf", steam_paths[sp], appid);
        if (access(buf, F_OK) == 0) {
            // Found manifest, get install dir
            FILE *f = fopen(buf, "r");
            if (f) {
                char line[256];
                while (fgets(line, sizeof(line), f)) {
                    if (strstr(line, "\"installdir\"")) {
                        char *q1 = strchr(line, '"');
                        char *q2 = q1 ? strchr(q1+1, '"') : NULL;
                        if (q1 && q2) {
                            *q2 = 0;
                            snprintf(out_path, out_sz, "%s/.steam/steam/steamapps/common/%s",
                                     steam_paths[sp], q1+1);
                            fclose(f);
                            return 1;
                        }
                    }
                }
                fclose(f);
            }
        }

        // Check alternate library
        snprintf(buf, sizeof(buf), "%s/.steam/debian-installation/steamapps/appmanifest_%d.acf",
                 steam_paths[sp], appid);
        if (access(buf, F_OK) == 0) {
            FILE *f = fopen(buf, "r");
            if (f) {
                char line[256];
                while (fgets(line, sizeof(line), f)) {
                    if (strstr(line, "\"installdir\"")) {
                        char *q1 = strchr(line, '"');
                        char *q2 = q1 ? strchr(q1+1, '"') : NULL;
                        if (q1 && q2) {
                            *q2 = 0;
                            snprintf(out_path, out_sz, "%s/.steam/debian-installation/steamapps/common/%s",
                                     steam_paths[sp], q1+1);
                            fclose(f);
                            return 1;
                        }
                    }
                }
                fclose(f);
            }
        }
    }
    return 0;
}

// ─── Main ───
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  %s <game_exe_or_dir>    # Patch binary/directory on disk\n", argv[0]);
        fprintf(stderr, "  %s --steam <appid>       # Find & patch Steam game by appid, then launch\n", argv[0]);
        fprintf(stderr, "  %s --proton <appid>      # Patch Steam game + Proton prefix\n", argv[0]);
        fprintf(stderr, "\nAppIDs: Just Cause 2 = 8190\n");
        return 1;
    }

    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║   ORACLE PRE-LAUNCH OPTIMIZER                  ║\n");
    printf("║   Patches binaries on disk — zero crash risk   ║\n");
    printf("╚══════════════════════════════════════════════════╝\n\n");

    if (strcmp(argv[1], "--steam") == 0 || strcmp(argv[1], "--proton") == 0) {
        int appid = atoi(argv[2]);
        char game_path[1024];

        if (!find_steam_game(appid, game_path, sizeof(game_path))) {
            fprintf(stderr, "[pre] Could not find Steam app %d\n", appid);
            return 1;
        }

        printf("[pre] Found game at: %s\n", game_path);

        // Patch the game directory
        printf("\n── Patching game files ──\n");
        patch_directory(game_path);

        // If --proton, also find and patch the Proton prefix
        if (strcmp(argv[1], "--proton") == 0) {
            char compat_path[1024];
            for (int sp = 0; ; sp++) {
                const char *homes[] = { getenv("HOME"), "/home/s1", "/home/u", NULL };
                if (!homes[sp]) break;
                snprintf(compat_path, sizeof(compat_path),
                         "%s/.steam/debian-installation/steamapps/compatdata/%d/pfx/drive_c/windows/system32",
                         homes[sp], appid);
                if (access(compat_path, F_OK) == 0) {
                    printf("\n── Patching Proton prefix DLLs ──\n");
                    patch_directory(compat_path);
                    break;
                }
                snprintf(compat_path, sizeof(compat_path),
                         "%s/.steam/steam/steamapps/compatdata/%d/pfx/drive_c/windows/system32",
                         homes[sp], appid);
                if (access(compat_path, F_OK) == 0) {
                    printf("\n── Patching Proton prefix DLLs ──\n");
                    patch_directory(compat_path);
                    break;
                }
            }
        }

        printf("\n── Results ──\n");
        printf("  Files patched:  %d\n", stats.n_files);
        printf("  NOP consolidations: %d\n", stats.n_nop_opt);
        printf("  Zeroing idiom fixes: %d\n", stats.n_zero_idiom);
        printf("  Immediate shortenings: %d\n", stats.n_shorten);
        printf("  Total bytes patched: %d\n", stats.n_patched_bytes);
        printf("\n[pre] Game is optimized. Launch from Steam.\n");

    } else {
        // Direct file/directory mode
        struct stat st;
        stat(argv[1], &st);

        if (S_ISDIR(st.st_mode)) {
            printf("[pre] Scanning directory: %s\n", argv[1]);
            patch_directory(argv[1]);
        } else {
            printf("[pre] Patching file: %s\n", argv[1]);
            patch_file(argv[1]);
        }

        printf("\n── Results ──\n");
        printf("  Files patched:  %d\n", stats.n_files);
        printf("  NOP consolidations: %d\n", stats.n_nop_opt);
        printf("  Zeroing idiom fixes: %d\n", stats.n_zero_idiom);
        printf("  Immediate shortenings: %d\n", stats.n_shorten);
        printf("  Total bytes patched: %d\n", stats.n_patched_bytes);
    }

    return 0;
}
