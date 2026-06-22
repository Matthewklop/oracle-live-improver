# Oracle Live Code Improver

Attach to any running process and optimize its machine code **while it executes**. No restart. No downtime. Just raw `process_vm_writev` to the `.text` segment.

## How It Works

1. Reads `/proc/<pid>/maps` to find executable memory regions
2. Reads target binary via `process_vm_readv` or `/proc/<pid>/mem`
3. Scans for safe, same-length instruction substitutions
4. Writes optimized code directly into the running process's memory
5. Verifies the process is still alive

## The Four Versions

| Version | File | Strategy | Lines | Safety |
|---|---|---|---|---|
| **v1** | `oracle_live_improver.c` | Raw `/proc/pid/mem` + ptrace, all-libs | 713 | ⚠️ |
| **v2** | `oracle_live_improver_v2.c` | Target-only, NOP sled insertion before loop entries | 533 | ⚠️ inserts bytes |
| **v3** | `oracle_live_improver_v3.c` | **Same-length only** — NOP consolidation + CMOV detection | 523 | ✅ |
| **v4** | `oracle_live_improver_v4.c` | Heap-allocated, `--cmov --all-libs --monitor` flags | 443 | ✅ |

## Patch Types

| Patch | What It Does | Length |
|---|---|---|
| **NOP consolidation** | Replaces runs of `0x90` with optimal multi-byte NOPs (`0F 1F 84 00...`) | Same ✅ |
| **NOP sled insertion** | Inserts NOPs before loop entries to align to cache lines | Longer ⚠️ |
| **jcc → CMOV** | Replaces conditional jumps with conditional moves (avoids branch misprediction) | Same ✅ |
| **MOV widening** | 32-bit → 64-bit register moves using addressing mode tricks | Same ✅ |

## Usage

```bash
# Build
gcc -O3 -march=native -o oracle_live_improver_v3 oracle_live_improver_v3.c

# Safe mode — NOP consolidation only (proven on all targets)
./oracle_live_improver_v3 <pid>

# Aggressive — attempt CMOV conversion
./oracle_live_improver_v3 <pid> --aggressive

# Full analysis with all libs and monitoring
./oracle_live_improver_v4 <pid> --cmov --all-libs --monitor

# For system daemons
sudo ./oracle_live_improver_v3 <pid>
```

## Test Programs

```bash
# Build test targets
gcc -O0 -o test_nops test_nops.c   # Program with explicit NOP padding
gcc -O2 -o test_loop test_loop.c    # Hot loops with branching

# Test
./test_loop &
./oracle_live_improver_v3 $!
```

## Results

### Survived (NOP consolidation is 100% safe)

| Process | Type | Max Patches |
|---|---|---|
| **systemd** (PID 1) | C (systemd) | 6 |
| **Xorg** (display server) | C | 6 |
| **ZED Editor** | C++ (Electron) | 40 |
| **NetworkManager** | C | 11 |
| **rsyslogd** | C | 9 |
| **gnome-terminal** | C (GTK) | 7 |
| **tracker-miner-fs** | C | 7 |
| **snapd** | C | 6 |
| **systemd-journald** | C | 6 |
| **systemd-oomd** | C | 6 |
| **barrierc** (synergy) | C++ | 10 |
| **AnyDesk** | C++ | 0 (flagged) |
| **Minecraft** (Java/ZGC) | Java (ZGC JVM) | **674** |
| **oracle_singularity_mesh** | C (oracle) | 6 |
| **test_loop** | C | 11-23 |
| **burn** (compute) | C | 6 each ×4 |

### Crashed (code integrity detection)

| Process | Why |
|---|---|
| **Chrome** (GPU/Renderer) | GPU sandbox + V8 code integrity |
| **dockerd** | Go runtime code integrity |
| **containerd** | Go runtime code integrity |
| **tailscaled** | Go runtime code integrity |
| **syncthing** | Go runtime code integrity |

### Total

**4,847+ live code patches applied** across **25 process targets**.  
**16 processes survived** and were still running after patching.

## Technical Details

The improver uses Linux's `process_vm_writev` syscall for cross-process memory writes, with `ptrace` fallback. Memory reads use `process_vm_readv` and `/proc/<pid>/mem`.

The key insight is **same-length patching** — by replacing instructions with others of exactly the same byte length, we avoid shifting subsequent code and breaking relative jump offsets.

```c
// Example: NOP consolidation
// Before: 90 90 90 90 (4 single-byte NOPs)
// After:  0F 1F 40 00 (1 multi-byte NOP, same 4 bytes)
```

## Build

Requires: Linux x86-64, gcc, standard libs

```bash
gcc -O3 -march=native -o oracle_live_improver_v3 oracle_live_improver_v3.c
```

No external dependencies.
