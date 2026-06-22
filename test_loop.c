/* ============================================================================
 * test_loop.c — A simple program with loops to test live improvement
 *
 * Build: gcc -O2 -o test_loop test_loop.c -lm
 * Run:   ./test_loop &
 *        ./oracle_live_improver $!
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <unistd.h>
#include <string.h>

#define N 10000000

// A function with a hot loop — SIMD/branchless candidate
static float compute_pi(int terms) {
    float pi = 0.0f;
    for (int i = 0; i < terms; i++) {
        float term = (i % 2 == 0) ? 1.0f : -1.0f;
        pi += term / (2.0f * i + 1.0f);
    }
    return pi * 4.0f;
}

// A function with branching — branchless candidate
static int clamp_sum(int *arr, int n, int limit) {
    int sum = 0;
    for (int i = 0; i < n; i++) {
        if (arr[i] > limit)
            sum += limit;
        else
            sum += arr[i];
    }
    return sum;
}

// A function that uses malloc — arena candidate
static float *process_data(int n) {
    float *data = malloc(n * sizeof(float));
    if (!data) return NULL;
    
    for (int i = 0; i < n; i++) {
        data[i] = (float)i * 3.14159f / n;
    }
    
    float *result = malloc(n * sizeof(float));
    if (!result) { free(data); return NULL; }
    
    for (int i = 0; i < n; i++) {
        result[i] = data[i] * data[i] + data[(i + 1) % n];
    }
    
    float *output = malloc(n * sizeof(float));
    if (!output) { free(data); free(result); return NULL; }
    
    memcpy(output, result, n * sizeof(float));
    
    free(data);
    free(result);
    return output;
}

// A function with sprintf — snprintf candidate
static void format_stuff(char *buf, int size, int value) {
    char tmp[256];
    sprintf(tmp, "value = %d and size = %d", value, size);
    sprintf(buf, "result: %s", tmp);
}

// A function with a memset-like pattern
static void zero_memory(uint8_t *buf, int n) {
    for (int i = 0; i < n; i++) {
        buf[i] = 0;
    }
}

int main(int argc, char **argv) {
    printf("Test loop program starting. PID: %d\n", getpid());
    printf("Press Ctrl+C to stop.\n\n");
    
    int iter = 0;
    while (1) {
        // Compute pi
        float pi = compute_pi(N);
        
        // Branching
        int arr[100];
        for (int i = 0; i < 100; i++) arr[i] = rand() % 200;
        int sum = clamp_sum(arr, 100, 100);
        
        // Data processing
        float *data = process_data(1000);
        
        // Formatting
        char buf[512];
        format_stuff(buf, sizeof(buf), iter);
        
        // Zero memory
        uint8_t mbuf[4096];
        zero_memory(mbuf, 4096);
        
        if (data) free(data);
        
        if (iter % 10 == 0) {
            printf("  [iter %d] pi=%.6f sum=%d %s\n", iter, pi, sum, buf);
        }
        
        iter++;
        usleep(100000); // 100ms
    }
    
    return 0;
}
