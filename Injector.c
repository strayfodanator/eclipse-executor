/*
 * Eclipse Executor — Injector
 *
 * Finds the Sober process, injects eclipse.so via ptrace + dlopen,
 * and applies optional memory patches.
 *
 * Usage:
 *   ./injector [pid] [lib_path]
 *   ./injector              — auto-find sober, inject ./eclipse.so
 *   ./injector 12345        — inject into PID 12345
 *   ./injector 12345 /path/to/eclipse.so
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>

/* ─── Logging helpers ───────────────────────────────────────────────── */

#define LOG_INFO(fmt, ...)  fprintf(stdout, "[injector] " fmt "\n", ##__VA_ARGS__)
#define LOG_ERR(fmt, ...)   fprintf(stderr, "[injector] ERROR: " fmt "\n", ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  fprintf(stderr, "[injector] WARN: " fmt "\n", ##__VA_ARGS__)

/* ─── Find PID by name ──────────────────────────────────────────────── */

pid_t find_pid(const char *name) {
    DIR *d = opendir("/proc");
    if (!d) {
        LOG_ERR("Could not open /proc: %s", strerror(errno));
        return -1;
    }

    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_type != DT_DIR) continue;

        pid_t pid = atoi(e->d_name);
        if (pid <= 0) continue;

        char path[PATH_MAX], exe[PATH_MAX];
        snprintf(path, sizeof(path), "/proc/%d/exe", pid);
        ssize_t len = readlink(path, exe, sizeof(exe) - 1);
        if (len == -1) continue;
        exe[len] = '\0';

        if (strstr(exe, name)) {
            closedir(d);
            LOG_INFO("Found process '%s' at PID %d (%s)", name, pid, exe);
            return pid;
        }
    }

    closedir(d);
    LOG_ERR("Process '%s' not found.", name);
    return -1;
}

/* ─── Get module base address ───────────────────────────────────────── */

unsigned long get_module_base(pid_t pid, const char *name) {
    char path[64], line[512];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) {
        LOG_ERR("Could not open %s: %s", path, strerror(errno));
        return 0;
    }

    unsigned long addr = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, name) && strstr(line, "r-xp")) {
            addr = strtoul(line, NULL, 16);
            break;
        }
    }
    fclose(f);

    if (addr == 0) {
        LOG_WARN("Module '%s' not found in PID %d maps.", name, pid);
    }
    return addr;
}

/* ─── Get symbol offset within a library ────────────────────────────── */

unsigned long get_offset(const char *lib, const char *sym) {
    void *h = dlopen(lib, RTLD_LAZY);
    if (!h) {
        LOG_WARN("Could not dlopen '%s' locally: %s", lib, dlerror());
        return 0;
    }

    void *sym_addr = dlsym(h, sym);
    if (!sym_addr) {
        LOG_WARN("Symbol '%s' not found in '%s': %s", sym, lib, dlerror());
        dlclose(h);
        return 0;
    }

    unsigned long local_base = get_module_base(getpid(), lib);
    if (local_base == 0) {
        LOG_WARN("Could not find local base for '%s'", lib);
        dlclose(h);
        return 0;
    }

    unsigned long offset = (unsigned long)sym_addr - local_base;
    dlclose(h);

    LOG_INFO("Resolved %s:%s -> offset 0x%lx", lib, sym, offset);
    return offset;
}

/* ─── Find dlopen in the target process ─────────────────────────────── */

static unsigned long resolve_remote_dlopen(pid_t pid) {
    /*
     * Try multiple strategies to find dlopen:
     *   1. libdl.so.2 (older systems)
     *   2. libc.so.6  (modern glibc where dlopen is in libc)
     *   3. libc.so    (alternative naming)
     */

    struct {
        const char *lib;
        const char *sym;
    } attempts[] = {
        { "libdl.so.2", "dlopen" },
        { "libc.so.6",  "dlopen" },
        { "libc.so.6",  "__libc_dlopen_mode" },
        { NULL, NULL }
    };

    for (int i = 0; attempts[i].lib; i++) {
        unsigned long remote_base = get_module_base(pid, attempts[i].lib);
        if (remote_base == 0) continue;

        unsigned long offset = get_offset(attempts[i].lib, attempts[i].sym);
        if (offset == 0) continue;

        unsigned long addr = remote_base + offset;
        LOG_INFO("Remote dlopen resolved via %s:%s at 0x%lx",
                 attempts[i].lib, attempts[i].sym, addr);
        return addr;
    }

    LOG_ERR("Could not resolve remote dlopen — all strategies failed.");
    return 0;
}

/* ─── Inject shared library via ptrace ──────────────────────────────── */

int inject(pid_t pid, const char *lib_path) {
    struct user_regs_struct old_regs, regs;
    int status;

    /* Resolve the absolute path of the library */
    char abs_path[PATH_MAX];
    if (realpath(lib_path, abs_path) == NULL) {
        LOG_ERR("Could not resolve path '%s': %s", lib_path, strerror(errno));
        return -1;
    }
    LOG_INFO("Library absolute path: %s", abs_path);

    /* Check if the library exists */
    if (access(abs_path, F_OK) != 0) {
        LOG_ERR("Library file not found: %s", abs_path);
        return -1;
    }

    /* Attach to the target */
    LOG_INFO("Attaching to PID %d...", pid);
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        LOG_ERR("PTRACE_ATTACH failed: %s", strerror(errno));
        LOG_ERR("Make sure you have the right permissions (try running as root or with CAP_SYS_PTRACE).");
        return -1;
    }

    waitpid(pid, &status, 0);
    if (!WIFSTOPPED(status)) {
        LOG_ERR("Process did not stop as expected (status: %d)", status);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }
    LOG_INFO("Attached and stopped.");

    /* Save original registers */
    if (ptrace(PTRACE_GETREGS, pid, NULL, &old_regs) < 0) {
        LOG_ERR("PTRACE_GETREGS failed: %s", strerror(errno));
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }
    memcpy(&regs, &old_regs, sizeof(regs));

    /* Resolve remote dlopen address */
    unsigned long target_dlopen = resolve_remote_dlopen(pid);
    if (!target_dlopen) {
        LOG_ERR("Aborting injection — dlopen not found.");
        ptrace(PTRACE_SETREGS, pid, NULL, &old_regs);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    /* Write the library path string onto the target's stack */
    regs.rsp -= 0x200;           /* Make room on the stack */
    regs.rsp &= ~0xFUL;         /* Align to 16 bytes */

    size_t path_len = strlen(abs_path) + 1;
    for (size_t i = 0; i < path_len; i += sizeof(long)) {
        long word = 0;
        size_t chunk = (path_len - i < sizeof(long)) ? path_len - i : sizeof(long);
        memcpy(&word, abs_path + i, chunk);
        if (ptrace(PTRACE_POKEDATA, pid, regs.rsp + i, word) < 0) {
            LOG_ERR("PTRACE_POKEDATA failed at offset %zu: %s", i, strerror(errno));
            ptrace(PTRACE_SETREGS, pid, NULL, &old_regs);
            ptrace(PTRACE_DETACH, pid, NULL, NULL);
            return -1;
        }
    }

    /* Set up the call: dlopen(path, RTLD_NOW) */
    regs.rdi = regs.rsp;        /* arg1: path */
    regs.rsi = RTLD_NOW;        /* arg2: flags */
    regs.rip = target_dlopen;   /* jump to dlopen */

    /* Push a return address that will cause a SIGSEGV (address 0) so we can catch it */
    regs.rsp -= 8;
    ptrace(PTRACE_POKEDATA, pid, regs.rsp, 0);

    /* Execute */
    LOG_INFO("Calling remote dlopen(0x%llx, RTLD_NOW) at 0x%lx...",
             (unsigned long long)regs.rdi, target_dlopen);

    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    ptrace(PTRACE_CONT, pid, NULL, NULL);

    /* Wait for dlopen to complete (it will SIGSEGV on return to addr 0) */
    waitpid(pid, &status, 0);

    if (WIFSTOPPED(status)) {
        int sig = WSTOPSIG(status);
        if (sig == SIGSEGV || sig == SIGTRAP) {
            /* Expected — dlopen returned to address 0 */
            struct user_regs_struct result_regs;
            ptrace(PTRACE_GETREGS, pid, NULL, &result_regs);
            if (result_regs.rax != 0) {
                LOG_INFO("dlopen returned handle: 0x%llx — injection successful!",
                         (unsigned long long)result_regs.rax);
            } else {
                LOG_WARN("dlopen returned NULL — library may have failed to load.");
                LOG_WARN("Check dlerror in the target process or /tmp/eclipse.log");
            }
        } else {
            LOG_WARN("Unexpected signal %d after dlopen call.", sig);
        }
    }

    /* Restore original state */
    ptrace(PTRACE_SETREGS, pid, NULL, &old_regs);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    LOG_INFO("Detached from PID %d.", pid);

    return 0;
}

/* ─── Memory patch ──────────────────────────────────────────────────── */

/*
 * Scans high memory regions in the target process for a known pattern
 * and applies a NOP patch. This is used to bypass specific checks.
 *
 * TODO: Document what this patch actually does and why the offset 0x1000d
 *       is subtracted from the match address.
 */
int patch(pid_t pid) {
    unsigned char pattern[] = "Java_com_roblox_protocols_localstor";
    size_t p_len = sizeof(pattern) - 1;
    unsigned long start = 0x700000000000UL;
    unsigned long end   = 0x800000000000UL;
    size_t c_size = 0x100000;

    unsigned char *buf = malloc(c_size);
    if (!buf) {
        LOG_ERR("OOM allocating scan buffer.");
        return -1;
    }

    LOG_INFO("Scanning memory region 0x%lx - 0x%lx for patch target...", start, end);

    for (unsigned long addr = start; addr < end; addr += c_size) {
        struct iovec local  = { buf, c_size };
        struct iovec remote = { (void *)addr, c_size };

        ssize_t read = process_vm_readv(pid, &local, 1, &remote, 1, 0);
        if (read <= 0) continue;

        for (size_t i = 0; i <= (size_t)read - p_len; i++) {
            if (memcmp(buf + i, pattern, p_len) == 0) {
                unsigned long match = addr + i;
                unsigned long target = match - 0x1000d;

                LOG_INFO("Pattern found at 0x%lx, patching at 0x%lx", match, target);

                unsigned char nop_patch[] = { 0x90, 0x90 };
                struct iovec pl = { nop_patch, 2 };
                struct iovec pr = { (void *)target, 2 };

                if (process_vm_writev(pid, &pl, 1, &pr, 1, 0) == 2) {
                    LOG_INFO("Patch applied successfully.");
                } else {
                    LOG_WARN("Patch write failed: %s", strerror(errno));
                }

                free(buf);
                return 0;
            }
        }
    }

    free(buf);
    LOG_WARN("Patch pattern not found in scanned range.");
    return -1;
}

/* ─── Main ──────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
    LOG_INFO("Eclipse Injector v0.2");

    pid_t pid;
    const char *lib_path = "./eclipse.so";

    if (argc >= 2) {
        /* First arg could be a PID */
        pid = atoi(argv[1]);
        if (pid <= 0) {
            LOG_ERR("Invalid PID: %s", argv[1]);
            return EXIT_FAILURE;
        }
    } else {
        pid = find_pid("sober");
        if (pid == -1) {
            LOG_ERR("Sober not running. Start Sober first, then run the injector.");
            return EXIT_FAILURE;
        }
    }

    if (argc >= 3) {
        lib_path = argv[2];
    }

    LOG_INFO("Target PID: %d", pid);
    LOG_INFO("Library: %s", lib_path);

    /* Step 1: Inject the library */
    if (inject(pid, lib_path) != 0) {
        LOG_ERR("Injection failed.");
        return EXIT_FAILURE;
    }

    /* Step 2: Apply memory patches */
    LOG_INFO("Applying memory patches...");
    patch(pid);

    LOG_INFO("Done.");
    return EXIT_SUCCESS;
}
