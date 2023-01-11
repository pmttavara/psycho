
// #define _NO_CRT_STDIO_INLINE

#define _CRT_SECURE_NO_WARNINGS

#include "spall_auto.h"

#include <stdio.h>
#include <stdint.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

__declspec(noinline) void print_hello_world(void) {
    // char b[512];
    // snprintf(b, sizeof b, "Hello, World!\n");
    volatile int x = 0;
    // if (x == 1) printf("Hello, World!\n");
}

DWORD thread_func(LPVOID p) {
    spall_auto_thread_init(/*GetCurrentThreadId(), SPALL_DEFAULT_BUFFER_SIZE, SPALL_DEFAULT_SYMBOL_CACHE_SIZE*/);

    for (int i = 0; i < 5000; i++) {
        print_hello_world();
    }
    for (int i = 0; i < 5000; i++) {
        print_hello_world();
    }
    for (int i = 0; i < 5000; i++) {
        print_hello_world();
    }

    spall_auto_thread_quit();
    return 0;
}

int main(void) {

    spall_auto_init("./psycho.spall");

    spall_auto_thread_init(/*GetCurrentThreadId(), SPALL_DEFAULT_BUFFER_SIZE, SPALL_DEFAULT_SYMBOL_CACHE_SIZE*/);

#if 1
    enum { N = 4 };
    HANDLE threads[N] = { 0 };
    for (uint64_t i = 0; i < N; i++) {
        threads[i] = CreateThread(NULL, 0, thread_func, NULL, 0, NULL);
        // SetThreadAffinityMask(threads[i], 1ull << i);
    }
    WaitForMultipleObjects(N, threads, TRUE, INFINITE);
#else
    thread_func(NULL);
#endif

    spall_auto_thread_quit();

    spall_auto_quit();

    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) { ExitProcess(main()); }

#define SPALL_AUTO_IMPLEMENTATION
#define SPALL_BUFFER_PROFILING
#define SPALL_BUFFER_PROFILING_GET_TIME() ((double)__rdtsc())
#include "spall_auto.h"
