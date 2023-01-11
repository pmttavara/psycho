#ifndef SPALL_AUTO_H
#define SPALL_AUTO_H

#ifdef __cplusplus
extern "C" {
#endif

void spall_auto_init(const char *filename);
void spall_auto_quit(void);

void spall_auto_thread_init(void);
void spall_auto_thread_flush(void);
void spall_auto_thread_quit(void);

void spall_auto_on(void);
void spall_auto_off(void);

extern unsigned long spall_auto__tls_index; // DWORD

// DO NOT CALL THIS DIRECTLY! Use spall_auto_begin() or spall_auto_begin_len() with one underscore
void spall_auto__begin_len(char *string, int length);
// DO NOT CALL THIS DIRECTLY! Use spall_auto_end() with one underscore
void spall_auto__end(void);

#ifndef _PROCESSTHREADSAPI_H_
extern __declspec(dllimport) void *(__stdcall TlsGetValue)(unsigned long dwTlsIndex);
extern __declspec(dllimport) int   (__stdcall TlsSetValue)(unsigned long dwTlsIndex, void *lpTlsValue);
#endif

// DO NOT MIX/MATCH THIS WITH spall_auto_on/spall_auto_off
#define spall_auto_thread_off() (spall_auto__tls_index == 0xFFFFFFFF ? 0 : TlsSetValue(spall_auto__tls_index, (void *)0))

// DO NOT MIX/MATCH THIS WITH spall_auto_on/spall_auto_off
#define spall_auto_thread_on() (spall_auto__tls_index == 0xFFFFFFFF ? 0 : TlsSetValue(spall_auto__tls_index, (void *)1))

#define spall_auto__reentrant(op) (spall_auto__tls_index == 0xFFFFFFFF ? 0 : TlsGetValue(spall_auto__tls_index) != (void *)1 ? 0 : (TlsSetValue(spall_auto__tls_index, (void *)0), (op), TlsSetValue(spall_auto__tls_index, (void *)1)))

#define spall_auto_begin_len(string, length) spall_auto__reentrant(spall_auto__begin_len(string, length))

#define spall_auto_begin(literal) spall_auto__reentrant(spall_auto__begin_len("" literal "", sizeof("" literal "") - 1))
#define spall_auto_end() spall_auto__reentrant(spall_auto__end())

#ifdef __cplusplus
}
#endif

#endif // SPALL_AUTO_H

#ifdef SPALL_AUTO_IMPLEMENTATION

#ifndef SPALL_AUTO_IMPLEMENTATED
#define SPALL_AUTO_IMPLEMENTATED

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "spall.h"

#define WIN32_LEAN_AND_MEAN
#define VC_EXTRALEAN
#define NOMINMAX
#include <Windows.h>
#include <DbgHelp.h>
#include <intrin.h>

#pragma comment(lib, "kernel32")
#pragma comment(lib, "user32")
#pragma comment(lib, "dbghelp")
#pragma comment(lib, "synchronization")

DWORD spall_auto__tls_index = 0xFFFFFFFF;
DWORD spall_auto__saved_tls_index = 0xFFFFFFFF;

static SpallProfile spall_auto__profile;
enum { SPALL_AUTO__BUFFER_SIZE = 1 << 24 };
__declspec(thread) static SpallBuffer spall_auto__buffer;
__declspec(thread) static int spall_auto_ready;
static DWORD spall_auto__pid;
__declspec(thread) static DWORD spall_auto__tid;

static inline uint64_t get_rdtsc_freq(void) {

    // Cache the answer so that multiple calls never take the slow path more than once
    static uint64_t tsc_freq = 0;
    if (tsc_freq) {
        return tsc_freq;
    }

    // Fast path: Load kernel-mapped memory page
    HMODULE ntdll = LoadLibraryA("ntdll.dll");
    if (ntdll) {

        int (*NtQuerySystemInformation)(int, void *, unsigned int, unsigned int *) =
            (int (*)(int, void *, unsigned int, unsigned int *))GetProcAddress(ntdll, "NtQuerySystemInformation");
        if (NtQuerySystemInformation) {

            volatile uint64_t *hypervisor_shared_page = NULL;
            unsigned int size = 0;

            // SystemHypervisorSharedPageInformation == 0xc5
            int result = (NtQuerySystemInformation)(0xc5, (void *)&hypervisor_shared_page, sizeof(hypervisor_shared_page), &size);

            // success
            if (size == sizeof(hypervisor_shared_page) && result >= 0) {
                // docs say ReferenceTime = ((VirtualTsc * TscScale) >> 64)
                //      set ReferenceTime = 10000000 = 1 second @ 10MHz, solve for VirtualTsc
                //       =>    VirtualTsc = 10000000 / (TscScale >> 64)
                tsc_freq = (10000000ull << 32) / (hypervisor_shared_page[1] >> 32);
                // If your build configuration supports 128 bit arithmetic, do this:
                // tsc_freq = ((unsigned __int128)10000000ull << (unsigned __int128)64ull) / hypervisor_shared_page[1];
            }
        }
        FreeLibrary(ntdll);
    }

    // Slow path
    if (!tsc_freq) {

        // Get time before sleep
        uint64_t qpc_begin = 0; QueryPerformanceCounter((LARGE_INTEGER *)&qpc_begin);
        uint64_t tsc_begin = __rdtsc();

        Sleep(2);

        // Get time after sleep
        uint64_t qpc_end = qpc_begin + 1; QueryPerformanceCounter((LARGE_INTEGER *)&qpc_end);
        uint64_t tsc_end = __rdtsc();

        // Do the math to extrapolate the RDTSC ticks elapsed in 1 second
        uint64_t qpc_freq = 0; QueryPerformanceFrequency((LARGE_INTEGER *)&qpc_freq);
        tsc_freq = (tsc_end - tsc_begin) * qpc_freq / (qpc_end - qpc_begin);
    }

    // Failure case
    if (!tsc_freq) {
        tsc_freq = 1000000000;
    }

    return tsc_freq;
}

SPALL_NOINSTRUMENT void spall_auto_on(void) {
    InterlockedExchange((volatile long *)&spall_auto__tls_index, spall_auto__saved_tls_index);
}
SPALL_NOINSTRUMENT void spall_auto_off(void) {
    InterlockedExchange((volatile long *)&spall_auto__tls_index, 0xFFFFFFFF);
}

SPALL_NOINSTRUMENT void spall_auto_init(const char *filename) {
    spall_auto__pid = GetCurrentProcessId();
    spall_auto__profile = spall_init_file(filename, 1000000.0 / get_rdtsc_freq());
    if (spall_auto__profile.data) {
        char temp_data[512];
        SpallBuffer temp = { temp_data, sizeof(temp_data) };
        spall_buffer_init(&spall_auto__profile, &temp);
        spall_buffer_begin_ex(&spall_auto__profile, &temp, "SymInitialize", sizeof("SymInitialize") - 1, (double)__rdtsc(), GetCurrentThreadId(), spall_auto__pid);
        SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES | SYMOPT_UNDNAME | SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_DEFERRED_LOADS);
        SymInitialize(GetCurrentProcess(), NULL, TRUE);
        spall_buffer_end_ex(&spall_auto__profile, &temp, (double)__rdtsc(), GetCurrentThreadId(), spall_auto__pid);
        spall_buffer_quit(&spall_auto__profile, &temp);

        if (spall_auto__saved_tls_index == 0xFFFFFFFF) {
            spall_auto__saved_tls_index = TlsAlloc();
        }
        spall_auto_on();
    }
}
SPALL_NOINSTRUMENT void spall_auto_quit(void) {
    spall_auto_off();
    if (spall_auto__saved_tls_index != 0xFFFFFFFF) {
        spall_quit(&spall_auto__profile);
    }
    SymCleanup(GetCurrentProcess());
}

enum { SPALL_AUTO__STRINGS_COUNT = 0x200000 };
typedef struct Spall_Auto__String {
    SYMBOL_INFO si;
    char name[256];
} Spall_Auto__String;
static __declspec(thread) Spall_Auto__String *spall_auto__strings;

SPALL_NOINSTRUMENT static void spall_auto__trace_begin(uint64_t address) {
    if (!spall_auto_ready) {
        return;
    }
    // spall_buffer_begin_ex(&spall_auto__profile, &spall_auto__buffer, "Auto Trace Begin", sizeof("Auto Trace Begin") - 1, (double)__rdtsc(), GetCurrentThreadId(), 0);

    char *ptr = 0;
    int length = 0;

    // n += snprintf(b, sizeof b, "0x%0.16p", address);

    enum { bitmask = SPALL_AUTO__STRINGS_COUNT - 1 };
    uint32_t key = (address >> 4) & bitmask;
    if (!spall_auto__strings[key].si.MaxNameLen) {
#if defined(_MSC_VER) && !defined(__clang__)
        address -= 5;
#endif

        static LONG sym_lock = 0;
        LONG locked = 1;

        while (InterlockedCompareExchange(&sym_lock, locked, 0) != 0) {
            WaitOnAddress(&sym_lock, &locked, sizeof(locked), INFINITE);
        }

        {
            spall_buffer_flush(&spall_auto__profile, &spall_auto__buffer);
            spall_buffer_begin_ex(&spall_auto__profile, &spall_auto__buffer, "Symbol Resolve", sizeof("Symbol Resolve") - 1, (double)__rdtsc(), spall_auto__tid, spall_auto__pid);

            SYMBOL_INFO *symbol = &spall_auto__strings[key].si;
            symbol->SizeOfStruct = sizeof(*symbol);
            symbol->MaxNameLen = sizeof(spall_auto__strings[key].name);

            DWORD64 dummy1 = 0;
            if (!SymFromAddr(GetCurrentProcess(), address, &dummy1, symbol)) {
                wsprintfA(symbol->Name, "(unknown 0x%08x%08x)", (uint32_t)(address >> 32ull), (uint32_t)address);
            }

            spall_buffer_end_ex(&spall_auto__profile, &spall_auto__buffer, (double)__rdtsc(), spall_auto__tid, spall_auto__pid);
        }

        InterlockedExchange(&sym_lock, 0);
        WakeByAddressSingle(&sym_lock);

    }

    ptr = spall_auto__strings[key].si.Name;
    length = spall_auto__strings[key].si.NameLen;

    double time = (double)__rdtsc();

    // printf("Entering %s (time: %f, tid: %u)\n", ptr, time, tid);

    // spall_buffer_end_ex(&spall_auto__profile, &spall_auto__buffer, (double)__rdtsc(), GetCurrentThreadId(), 0);
    spall_buffer_begin_ex(&spall_auto__profile, &spall_auto__buffer, ptr, length, time, spall_auto__tid, spall_auto__pid);
}

SPALL_NOINSTRUMENT static void spall_auto__trace_end() {
    if (!spall_auto_ready) {
        return;
    }

    double time = (double)__rdtsc();

    // printf("Exiting (time: %f, tid: %u)\n", time, tid);

    spall_buffer_end_ex(&spall_auto__profile, &spall_auto__buffer, time, spall_auto__tid, spall_auto__pid);
}



#define BE(_0,_1,_2,_3,_4,_5,_6,_7,NOTHING) \
    ((uin ## NOTHING ## t64_t)(_7) << 56 | \
     (uin ## NOTHING ## t64_t)(_6) << 48 | \
     (uin ## NOTHING ## t64_t)(_5) << 40 | \
     (uin ## NOTHING ## t64_t)(_4) << 32 | \
     (uin ## NOTHING ## t64_t)(_3) << 24 | \
     (uin ## NOTHING ## t64_t)(_2) << 16 | \
     (uin ## NOTHING ## t64_t)(_1) <<  8 | \
     (uin ## NOTHING ## t64_t)(_0) <<  0)

// 0x90,
// 0x66,0x90,
// 0x0F,0x1F,0x00,
// 0x0F,0x1F,0x40,0x00,
// 0x0F,0x1F,0x44,0x00,0x00,
// 0x66,0x0F,0x1F,0x44,0x00,0x00,
// 0x0F,0x1F,0x80,0x00,0x00,0x00,0x00,
// 0x0F,0x1F,0x84,0x00,0x00,0x00,0x00,0x00,
// 0x66,0x0F,0x1F,0x84,0x00,0x00,0x00,0x00,0x00,

#define PHOOK_CAT__(a, b) a##b
#define PHOOK_CAT_(a, b) PHOOK_CAT__(a, b)
#define PHOOK_CAT(a, b) PHOOK_CAT_(a, b)
#define PHOOK_UNWRAP(...) __VA_ARGS__
#define PHOOK_IF_1(a, b) a
#define PHOOK_IF_0(a, b) b
#define PHOOK_IF(cond, a, b) PHOOK_CAT(PHOOK_IF_, cond)(PHOOK_UNWRAP a, PHOOK_UNWRAP b)
#define PHOOK(name, ENT, dest) \
__declspec(allocate(".text")) __declspec(dllexport) extern const uint64_t name[] = { \
    BE( \
        0x0F,0x1F,0x00,                                         /* nop */ \
        0x9C,                                                   /* pushf */ \
        0x50,                                                   /* push rax */ \
        0x51,                                                   /* push rcx */ \
        0x48,0xB8,                                              /* mov rax, spall_auto__tls_index */ \
    ),(uint64_t)&spall_auto__tls_index,BE(                      /* abs64 relocation */ \
        0x83,0x38,0xFF,                                         /* cmp qword ptr [rax], 0xFFFFFFFF */ \
        0x75,0x04,                                              /* jne IS_PROFILING */ \
                                                                /* REENTRANT: */ \
        0x59,                                                   /* pop rcx */ \
        0x58,                                                   /* pop rax */ \
        0x9D,                                                   /* popf */ \
    ),BE( \
        0xC3,                                                   /* ret */ \
                                                                /* IS_PROFILING: */ \
        0x8B,0x08,                                              /* mov ecx, dword ptr [rax] */ \
                                                                /* check if we're already inside of penter, if so then don't call again */ \
        0x65,0x48,0x8B,0x04,0x25,),BE(0x30,0x00,0x00,0x00,      /* mov rax, qword ptr gs:[0x30] */ \
        0x48,0x8D,0x8C,0xC8,),BE(0x80,0x14,0x00,0x00,           /* lea rcx, [rax+rcx*8+0x1480] */ \
        0x83,0x39,0x01,                                         /* cmp dword ptr [rcx], 1 */ \
        0x75,),BE(0xE4,                                         /* jne REENTRANT */ \
        0x49,0x50,                                              /* push r8 */ \
                                                                /* clone rsp into rdx and round down to 16 byte boundary to satisfy ABI */ \
        0x52,                                                   /* push rdx */ \
        0x48,0x89,0xE2,                                         /* mov rdx, rsp */ \
        0x48,),BE(0x83,0xE4,0xF0,                               /* and rsp, 0xfffffffffffffff0 */ \
        0xC6,0x01,0x00,                                         /* mov byte ptr [rcx], 0 */ \
        0x48,0xB8,                                              /* mov rax, spall_auto_trace */ \
    ),(uint64_t)dest,BE(                                        /* abs64 relocation */ \
        0x52,                                                   /* push rdx */ \
        0x49,0x51,                                              /* push r9 */ \
        0x49,0x52,                                              /* push r10 */ \
        0x49,0x53,                                              /* push r11 */ \
        0x51,                                                   /* push rcx */ \
    ),BE( \
        0x48,0x81,0xEC,0x88,0x00,0x00,0x00,                     /* sub rsp, 0x88 */ \
        0x0F,),BE(0x29,0x44,0x24,0x70,                          /* movaps xmmword ptr [rsp+0x70], xmm0 */ \
        0x0F,0x29,0x4C,0x24,),BE(0x60,                          /* movaps xmmword ptr [rsp+0x60], xmm1 */ \
        0x0F,0x29,0x54,0x24,0x50,                               /* movaps xmmword ptr [rsp+0x50], xmm2 */ \
        0x0F,0x29,),BE(0x5C,0x24,0x40,                          /* movaps xmmword ptr [rsp+0x40], xmm3 */ \
        0x0F,0x29,0x64,0x24,0x30,                               /* movaps xmmword ptr [rsp+0x30], xmm4 */ \
    ), \
    PHOOK_IF(ENT, (                                             /* if ENT */ \
        BE( \
            0x0F,0x29,0x6C,0x24,0x20,                               /* movaps xmmword ptr [rsp+0x20], xmm5 */ \
            0x48,0x8B,0x4A,),BE(0x28,                               /* mov rcx, [rdx+0x28] */ \
            0xFF,0xD0,                                              /* call rax */ \
            0x0F,0x28,0x6C,0x24,0x20,                               /* movaps xmm3, xmmword ptr [rsp+0x20] */ \
        ) \
    ),(                                                         /* else */ \
        BE( \
            0x0F,0x29,0x6C,0x24,0x20,                               /* movaps xmmword ptr [rsp+0x20], xmm5 */ \
            0x0F,0x1F,0x40,),BE(0x00,                               /* nop */ \
            0xFF,0xD0,                                              /* call rax */ \
            0x0F,0x28,0x6C,0x24,0x20,                               /* movaps xmm3, xmmword ptr [rsp+0x20] */ \
        ) \
    )),                                                         /* endif */ \
    BE( \
        0x0F,0x28,0x64,0x24,0x30,                               /* movaps xmm3, xmmword ptr [rsp+0x30] */ \
        0x0F,0x28,0x5C,),BE(0x24,0x40,                          /* movaps xmm3, xmmword ptr [rsp+0x40] */ \
        0x0F,0x28,0x54,0x24,0x50,                               /* movaps xmm2, xmmword ptr [rsp+0x50] */ \
        0x0F,),BE(0x28,0x4C,0x24,0x60,                          /* movaps xmm1, xmmword ptr [rsp+0x60] */ \
        0x0F,0x28,0x44,0x24,),BE(0x70,                          /* movaps xmm0, xmmword ptr [rsp+0x70] */ \
        0x48,0x81,0xC4,0x88,0x00,0x00,0x00,                     /* add rsp, 0x88 */ \
    ),BE( \
        0x59,                                                   /* pop rcx */ \
        0xC6,0x01,0x01,                                         /* mov byte ptr [rcx], 1 */ \
        0x49,0x5B,                                              /* pop r11 */ \
        0x49,0x5A,                                              /* pop r10 */ \
    ),BE( \
        0x49,0x59,                                              /* pop r9 */ \
        0x5C,                                                   /* pop rsp */ \
        0x5A,                                                   /* pop rdx */ \
        0x49,0x58,                                              /* pop r8 */ \
        0x59,                                                   /* pop rcx */ \
        0x58,                                                   /* pop rax */ \
    ),BE( \
        0x9D,                                                   /* popf */ \
        0xC3,                                                   /* ret */ \
        0xCC,                                                   /* int3 */ \
        0xCC,                                                   /* int3 */ \
        0xCC,                                                   /* int3 */ \
        0xCC,                                                   /* int3 */ \
        0xCC,                                                   /* int3 */ \
        0xCC,                                                   /* int3 */ \
    ), \
};

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wextern-initializer"
#else
#pragma code_seg(".text")
#endif
PHOOK(_penter, 1, spall_auto__trace_begin);
PHOOK(_pexit,  0, spall_auto__trace_end);
#ifdef __clang__
#pragma clang diagnostic pop
#endif

SPALL_NOINSTRUMENT void spall_auto_thread_init(void) {
    if (!spall_auto_ready) {
        spall_auto__tid = GetCurrentThreadId();
        if (spall_auto__profile.data) {
            size_t n = SPALL_AUTO__BUFFER_SIZE + sizeof(spall_auto__strings[0]) * SPALL_AUTO__STRINGS_COUNT;
            spall_auto__buffer.data = calloc(n, 1);
            if (spall_auto__buffer.data) {
                spall_auto__strings = (Spall_Auto__String *)((char *)spall_auto__buffer.data + SPALL_AUTO__BUFFER_SIZE);
                spall_auto__buffer.length = SPALL_AUTO__BUFFER_SIZE;
                if (spall_auto__buffer.length <= (1 << 24)) {
                    memset(spall_auto__buffer.data, 1, spall_auto__buffer.length);
                }
                if (spall_buffer_init(&spall_auto__profile, &spall_auto__buffer)) {
                    spall_auto_ready = 1;

                    spall_auto_thread_on();
                } else {
                    free(spall_auto__buffer.data);
                    memset(&spall_auto__buffer, 0, sizeof(spall_auto__buffer));
                    spall_auto__strings = NULL;
                }
            }
        }
    }

    // spall_auto__trace_begin((uint64_t)_ReturnAddress());
    // spall_auto__trace_end((uint64_t)_ReturnAddress());
}

SPALL_NOINSTRUMENT void spall_auto_thread_flush(void) {
    spall_buffer_flush(&spall_auto__profile, &spall_auto__buffer);
}

SPALL_NOINSTRUMENT void spall_auto_thread_quit(void) {
    if (spall_auto_ready) {
        spall_auto_thread_off();
        spall_auto_ready = 0;
        spall_buffer_quit(&spall_auto__profile, &spall_auto__buffer);
        free(spall_auto__buffer.data);
        memset(&spall_auto__buffer, 0, sizeof(spall_auto__buffer));
        spall_auto__strings = NULL;
    }
}

SPALL_NOINSTRUMENT void spall_auto__begin_len(char *string, int length) {
    if (!spall_auto_ready) {
        return;
    }
    spall_buffer_begin_ex(&spall_auto__profile, &spall_auto__buffer, string, length, (double)__rdtsc(), spall_auto__tid, spall_auto__pid);
}
SPALL_NOINSTRUMENT void spall_auto__end(void) {
    if (!spall_auto_ready) {
        return;
    }
    spall_buffer_end_ex(&spall_auto__profile, &spall_auto__buffer, (double)__rdtsc(), spall_auto__tid, spall_auto__pid);
}

SPALL_NOINSTRUMENT extern void __cyg_profile_func_enter(void* fn, void* caller) {
    (void)caller;
    spall_auto__trace_begin((uint64_t)fn);
}
SPALL_NOINSTRUMENT extern void __cyg_profile_func_exit(void* fn, void* caller) {
    (void)fn;
    (void)caller;
    spall_auto__trace_end();
}

#ifdef __cplusplus
}
#endif

#endif // SPALL_AUTO_IMPLEMENTATED

#endif // SPALL_AUTO_IMPLEMENTATION
