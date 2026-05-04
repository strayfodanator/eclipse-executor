#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/uio.h>
#include <stdint.h>

int main() {
    pid_t pid = 172240;
    uintptr_t str_addr = 0;
    uint8_t *buffer = malloc(1024 * 1024);

    // Passo 1: Achar a string em qualquer lugar
    FILE* f = fopen("/proc/172240/maps", "r");
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        unsigned long s, e;
        if (sscanf(line, "%lx-%lx", &s, &e) < 2) continue;
        for (unsigned long addr = s; addr < e; addr += 1024 * 1024) {
            size_t chunk = (e - addr < 1024 * 1024) ? (e - addr) : 1024 * 1024;
            struct iovec local = {buffer, chunk}, remote = {(void*)addr, chunk};
            if (process_vm_readv(pid, &local, 1, &remote, 1, 0) > 0) {
                for (size_t i = 0; i < chunk - 10; i++) {
                    if (memcmp(buffer + i, "loadstring", 10) == 0) {
                        str_addr = addr + i;
                        printf("[FOUND] String at 0x%lx\n", str_addr);
                    }
                }
            }
        }
    }

    if (str_addr) {
        // Passo 2: Achar XREFs na região r-xp de 56MB
        uintptr_t engine_start = 0x7f1922524000;
        size_t engine_size = 59518976;
        uint8_t *ebuf = malloc(engine_size);
        struct iovec l2 = {ebuf, engine_size}, r2 = {(void*)engine_start, engine_size};
        if (process_vm_readv(pid, &l2, 1, &r2, 1, 0) == (ssize_t)engine_size) {
            for (size_t i = 0; i < engine_size - 7; i++) {
                if (ebuf[i] == 0x48 && ebuf[i+1] == 0x8d) { // LEA
                    int32_t rel = *(int32_t*)(&ebuf[i+3]);
                    if (engine_start + i + 7 + rel == str_addr) {
                        printf("[FOUND] XREF at 0x%lx (Offset from region start: 0x%lx)\n", engine_start + i, i);
                    }
                }
            }
        }
        free(ebuf);
    }
    return 0;
}
