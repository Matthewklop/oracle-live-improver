/* ============================================================================
 * test_nops.c — Program with explicit NOP padding for testing
 * Build: gcc -O0 -o test_nops test_nops.c
 * ============================================================================
 */
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

// Force some NOP padding with inline asm
static int compute(int n) {
    int sum = 0;
    for (int i = 0; i < n; i++) {
        asm volatile("nop\n\tnop\n\tnop\n\t");
        if (i % 2 == 0)
            sum += i * 3;
        else
            sum += i * 7;
        asm volatile("nop\n\t");
    }
    return sum;
}

static int clamp(int val, int limit) {
    if (val > limit) return limit;
    if (val < -limit) return -limit;
    return val;
}

int main() {
    printf("test_nops PID: %d\n", getpid());
    volatile int sink = 0;
    while (1) {
        sink += compute(10000);
        sink = clamp(sink, 1000000);
        usleep(50000);
        static int c = 0;
        if (++c % 20 == 0) printf(".");
        fflush(stdout);
    }
    return 0;
}
