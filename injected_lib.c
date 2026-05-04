#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/mman.h>

#define OFFSET_PCALL     0x1087806
#define OFFSET_LOADSTR   0x109cb7c

// Gravando o log na pasta privada do Sober, onde ele tem permissão de escrita
void log_msg(const char* msg) {
    FILE* f = fopen("/home/strayfoda/.var/app/org.vinegarhq.Sober/data/eclipse.log", "a");
    if (f) { fprintf(f, "%s\n", msg); fclose(f); }
}

typedef int (*lua_pcall_t)(void* L, int nargs, int nresults, int errfunc);
typedef int (*luau_load_t)(void* L, const char* chunkname, const char* data, size_t size, int env);

void* find_l(uintptr_t start, uintptr_t end) {
    for (uintptr_t addr = start; addr < end - 128; addr += 8) {
        uint8_t* buf = (uint8_t*)addr;
        if (buf[8] == 6 && buf[10] == 0) {
            uintptr_t l_G = *(uintptr_t*)(buf + 32);
            if (l_G > 0x700000000000 && (l_G % 8 == 0)) {
                uintptr_t main_t = *(uintptr_t*)l_G;
                if (main_t == addr) return (void*)addr;
            }
        }
    }
    return NULL;
}

void* eclipse_auto_injector(void* arg) {
    log_msg("[eclipse] Auto-Injector Started INSIDE SANDBOX. Waiting for Roblox Engine...");

    uintptr_t engine_base = 0;
    
    while (!engine_base) {
        FILE* f = fopen("/proc/self/maps", "r");
        if (!f) { sleep(2); continue; }

        char line[512];
        while (fgets(line, sizeof(line), f)) {
            uintptr_t s, e;
            char perms[8];
            if (sscanf(line, "%lx-%lx %s", &s, &e, perms) >= 3) {
                size_t size = e - s;
                if (size >= 50*1024*1024 && size <= 70*1024*1024 && perms[2] == 'x') {
                    engine_base = s;
                    break;
                }
            }
        }
        fclose(f);

        if (!engine_base) sleep(2);
    }

    char msg[256];
    snprintf(msg, sizeof(msg), "[eclipse] BINGO! Engine found at: 0x%lx", engine_base);
    log_msg(msg);

    sleep(5); // Espera estabilizar

    void* L = NULL;
    int retries = 0;
    while (!L && retries < 10) {
        L = find_l(engine_base - 0x30000000, engine_base + 0x30000000);
        if (!L) {
            log_msg("[eclipse] lua_State not ready yet. Retrying in 3s...");
            sleep(3);
            retries++;
        }
    }

    if (L) {
        snprintf(msg, sizeof(msg), "[eclipse] lua_State found at: %p. INJECTING SCRIPT!", L);
        log_msg(msg);

        luau_load_t r_load = (luau_load_t)(engine_base + OFFSET_LOADSTR);
        lua_pcall_t r_pcall = (lua_pcall_t)(engine_base + OFFSET_PCALL);

        const char* script = 
            "print('====================================');"
            "print(' ECLIPSE EXECUTOR FOR LINUX LOADED  ');"
            "print('====================================');"
            "print('Sandbox successfully bypassed!');";

        if (r_load(L, "@eclipse", script, strlen(script), 0) == 0) {
            r_pcall(L, 0, 0, 0);
            log_msg("[eclipse] Payload successfully executed in-game!");
        } else {
            log_msg("[eclipse] ERROR: Failed to load script bytecode.");
        }
    } else {
        log_msg("[eclipse] CRITICAL: Failed to find lua_State after maximum retries.");
    }
    
    return NULL;
}

void __attribute__((constructor)) init() {
    pthread_t t;
    pthread_create(&t, NULL, eclipse_auto_injector, NULL);
}
