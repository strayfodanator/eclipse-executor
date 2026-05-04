#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <dlfcn.h>
#include <elf.h>

// Helper to write memory to another process
void ptrace_write(pid_t pid, uintptr_t addr, void *vptr, int len) {
    int byteCount = 0;
    long word = 0;
    while (byteCount < len) {
        memcpy(&word, (uint8_t*)vptr + byteCount, sizeof(word));
        ptrace(PTRACE_POKEDATA, pid, addr + byteCount, word);
        byteCount += sizeof(word);
    }
}

// Shellcode for x86_64 to call dlopen
// mov rdi, path_addr
// mov rsi, 2 (RTLD_NOW)
// mov rax, dlopen_addr
// call rax
// int3
unsigned char shellcode[] = {
    0x48, 0xBF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rdi, 0x0
    0x48, 0xBE, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rsi, 2
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 0x0
    0xFF, 0xD0,                                                 // call rax
    0xCC                                                        // int3 (breakpoint)
};

uintptr_t get_libc_base(pid_t pid) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "libc.so.6") && strstr(line, "r-xp")) {
            uintptr_t base;
            sscanf(line, "%lx", &base);
            fclose(f);
            return base;
        }
    }
    fclose(f);
    return 0;
}

uintptr_t get_local_dlopen_offset() {
    FILE *f = fopen("/proc/self/maps", "r");
    char line[512];
    uintptr_t base = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "libc.so.6") && strstr(line, "r-xp")) {
            sscanf(line, "%lx", &base);
            break;
        }
    }
    fclose(f);
    if (!base) return 0;
    return (uintptr_t)dlopen - base;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        printf("Usage: %s <pid> <lib_path>\n", argv[0]);
        return 1;
    }

    pid_t target_pid = atoi(argv[1]);
    const char* lib_path = argv[2];

    uintptr_t libc_base = get_libc_base(target_pid);
    if (!libc_base) {
        printf("[!] Could not find libc in target.\n");
        return 1;
    }

    uintptr_t dlopen_offset = get_local_dlopen_offset();
    uintptr_t dlopen_addr = libc_base + dlopen_offset;
    printf("[+] Target libc base: 0x%lx\n", libc_base);
    printf("[+] Target dlopen addr: 0x%lx\n", dlopen_addr);

    if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) < 0) {
        perror("ptrace attach");
        return 1;
    }
    waitpid(target_pid, NULL, 0);

    struct user_regs_struct regs, old_regs;
    ptrace(PTRACE_GETREGS, target_pid, NULL, &old_regs);
    regs = old_regs;

    // Use current RIP as a scratchpad (we will restore it later)
    uintptr_t scratch_addr = regs.rip;
    uintptr_t string_addr = scratch_addr + sizeof(shellcode);

    // Patch shellcode with actual addresses
    *(uintptr_t*)(&shellcode[2]) = string_addr;
    *(uintptr_t*)(&shellcode[22]) = dlopen_addr;

    // Save old instructions
    size_t total_len = sizeof(shellcode) + strlen(lib_path) + 1;
    uint8_t* backup = malloc(total_len + 8);
    
    struct iovec local = {backup, total_len + 8}, remote = {(void*)scratch_addr, total_len + 8};
    process_vm_readv(target_pid, &local, 1, &remote, 1, 0);

    // Write shellcode and string
    uint8_t* payload = malloc(total_len + 8);
    memcpy(payload, shellcode, sizeof(shellcode));
    memcpy(payload + sizeof(shellcode), lib_path, strlen(lib_path) + 1);
    ptrace_write(target_pid, scratch_addr, payload, total_len + 8);

    // Set RIP to shellcode and continue
    regs.rip = scratch_addr;
    ptrace(PTRACE_SETREGS, target_pid, NULL, &regs);
    ptrace(PTRACE_CONT, target_pid, NULL, NULL);

    // Wait for int3 (SIGTRAP)
    int status;
    waitpid(target_pid, &status, 0);

    // Check RAX (return value of dlopen)
    ptrace(PTRACE_GETREGS, target_pid, NULL, &regs);
    printf("[+] dlopen returned: 0x%llx\n", regs.rax);

    // Restore old instructions and registers
    ptrace_write(target_pid, scratch_addr, backup, total_len + 8);
    ptrace(PTRACE_SETREGS, target_pid, NULL, &old_regs);
    ptrace(PTRACE_DETACH, target_pid, NULL, NULL);

    printf("[+] Done!\n");
    return 0;
}
