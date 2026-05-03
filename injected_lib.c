/*
 * Eclipse Executor — Injected Library (eclipse.so)
 *
 * This shared library is injected into the Sober process by the injector.
 * On load, it:
 *   1. Starts a listener thread on a named pipe (/tmp/eclipse_pipe)
 *   2. Attempts to locate Luau execution functions via pattern scanning
 *   3. Loads and runs init.lua to set up the scripting environment
 *   4. Waits for scripts from the UI and executes them
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <errno.h>
#include <stdint.h>
#include <stdarg.h>
#include <link.h>

#define ECLIPSE_PIPE_PATH "/tmp/eclipse_pipe"
#define ECLIPSE_LOG_PATH  "/tmp/eclipse.log"
#define INIT_LUA_PATH     "./init.lua"

/* ─── Logging ───────────────────────────────────────────────────────── */

static FILE *logfile = NULL;

static void eclipse_log(const char *fmt, ...) {
    if (!logfile) {
        logfile = fopen(ECLIPSE_LOG_PATH, "a");
        if (!logfile) return;
    }
    va_list args;
    va_start(args, fmt);
    fprintf(logfile, "[eclipse] ");
    vfprintf(logfile, fmt, args);
    fprintf(logfile, "\n");
    fflush(logfile);
    va_end(args);
}

/* ─── libroblox module base ─────────────────────────────────────────── */

static unsigned long get_lib_base(const char *name) {
    char line[512];
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;

    unsigned long addr = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, name) && strstr(line, "r-xp")) {
            addr = strtoul(line, NULL, 16);
            break;
        }
    }
    fclose(f);
    return addr;
}

/* ─── Pattern Scanning ──────────────────────────────────────────────── */

/*
 * Scans memory from `start` for `size` bytes looking for `pattern`.
 * `mask` uses 'x' for must-match and '?' for wildcard.
 * Returns the address of the first match or 0.
 */
__attribute__((unused))
static unsigned long pattern_scan(unsigned long start, size_t size,
                                  const unsigned char *pattern, const char *mask) {
    size_t pat_len = strlen(mask);
    const unsigned char *mem = (const unsigned char *)start;

    for (size_t i = 0; i <= size - pat_len; i++) {
        int found = 1;
        for (size_t j = 0; j < pat_len; j++) {
            if (mask[j] == 'x' && mem[i + j] != pattern[j]) {
                found = 0;
                break;
            }
        }
        if (found) return start + i;
    }
    return 0;
}

/* ─── Luau Execution Types ──────────────────────────────────────────── */

/*
 * These typedefs represent the Luau C API functions we need to find.
 * The actual offsets/signatures depend on the specific Roblox build.
 *
 * TODO: Fill in real AOB patterns or offsets for the current Sober build.
 */

typedef void* lua_State;

/* int luau_load(lua_State* L, const char* chunkname, const char* data, size_t size, int env) */
typedef int (*luau_load_t)(lua_State *L, const char *chunkname, const char *data, size_t size, int env);

/* int lua_pcall(lua_State* L, int nargs, int nresults, int errfunc) */
typedef int (*lua_pcall_t)(lua_State *L, int nargs, int nresults, int errfunc);

/* void lua_getfield(lua_State* L, int idx, const char* k) */
typedef void (*lua_getfield_t)(lua_State *L, int idx, const char *k);

/* void lua_settop(lua_State* L, int idx) */
typedef void (*lua_settop_t)(lua_State *L, int idx);

/* const char* lua_tolstring(lua_State* L, int idx, size_t* len) */
typedef const char* (*lua_tolstring_t)(lua_State *L, int idx, size_t *len);

/* void lua_pushvalue(lua_State* L, int idx) */
typedef void (*lua_pushvalue_t)(lua_State *L, int idx);

/* Resolved function pointers */
static lua_State         *g_lua_state  = NULL;
static luau_load_t        f_luau_load  = NULL;
static lua_pcall_t        f_lua_pcall  = NULL;
static lua_getfield_t     f_lua_getfield __attribute__((unused)) = NULL;
static lua_settop_t       f_lua_settop = NULL;
static lua_tolstring_t    f_lua_tolstring = NULL;
static lua_pushvalue_t    f_lua_pushvalue __attribute__((unused)) = NULL;

/* ─── Chat message (fallback for printing) ──────────────────────────── */

typedef void (*GameSendChatFunc)(const char *msg, int type);

/* TODO: Update this offset for your build of libroblox.so */
#define GAME_SEND_CHAT_MESSAGE_FUNCTION_OFFSET 0x16D2D00

static void print_chat(const char *message) {
    unsigned long base = get_lib_base("libroblox.so");
    if (base == 0) return;

    unsigned long chat_func_addr = base + GAME_SEND_CHAT_MESSAGE_FUNCTION_OFFSET;
    GameSendChatFunc send_chat = (GameSendChatFunc)chat_func_addr;
    if (send_chat) {
        send_chat(message, 0);
    }
}

/* ─── Resolve Luau functions ────────────────────────────────────────── */

/*
 * Attempt to find the Luau API functions inside libroblox.so.
 * Strategy:
 *   1. Use known offsets (fastest, but breaks on updates)
 *   2. Use AOB pattern scan (more resilient)
 *   3. Fallback: scan for known string refs
 *
 * TODO: Fill in real offsets or AOB patterns for the target build.
 */

/* Example known offsets — replace with real ones */
#define LUAU_LOAD_OFFSET    0x0  /* TODO */
#define LUA_PCALL_OFFSET    0x0  /* TODO */
#define LUA_GETFIELD_OFFSET 0x0  /* TODO */
#define LUA_SETTOP_OFFSET   0x0  /* TODO */
#define LUA_TOLSTRING_OFFSET 0x0 /* TODO */
#define LUA_PUSHVALUE_OFFSET 0x0 /* TODO */

/*
 * Example AOB signatures — replace with real patterns.
 * Pattern bytes use 0x00 as placeholder for '?' mask positions.
 *
 * Usage:
 *   unsigned char sig[] = { 0x55, 0x48, 0x89, 0xe5, ... };
 *   const char  mask[]  = "xxxx????xxxx";
 */

static int resolve_luau_functions(void) {
    unsigned long base = get_lib_base("libroblox.so");
    if (base == 0) {
        eclipse_log("libroblox.so not found in memory maps.");
        return -1;
    }

    eclipse_log("libroblox.so base: 0x%lx", base);

    /*
     * Strategy 1: Known offsets
     * Uncomment and fill in when you have confirmed offsets.
     */
#if LUAU_LOAD_OFFSET != 0
    f_luau_load   = (luau_load_t)(base + LUAU_LOAD_OFFSET);
    f_lua_pcall   = (lua_pcall_t)(base + LUA_PCALL_OFFSET);
    f_lua_getfield = (lua_getfield_t)(base + LUA_GETFIELD_OFFSET);
    f_lua_settop  = (lua_settop_t)(base + LUA_SETTOP_OFFSET);
    f_lua_tolstring = (lua_tolstring_t)(base + LUA_TOLSTRING_OFFSET);
    f_lua_pushvalue = (lua_pushvalue_t)(base + LUA_PUSHVALUE_OFFSET);
    eclipse_log("Luau functions resolved via known offsets.");
    return 0;
#endif

    /*
     * Strategy 2: AOB Pattern Scanning
     * Scan the executable region of libroblox.so for known byte patterns.
     *
     * TODO: Fill in real AOB patterns for luau_load, lua_pcall, etc.
     *
     * Example (placeholder):
     *
     *   unsigned char luau_load_sig[] = { 0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, ... };
     *   const char   luau_load_mask[] = "xxxxxx????xxxx";
     *
     *   unsigned long addr = pattern_scan(base, 0x2000000, luau_load_sig, luau_load_mask);
     *   if (addr) {
     *       f_luau_load = (luau_load_t)addr;
     *       eclipse_log("luau_load found at 0x%lx", addr);
     *   }
     */

    eclipse_log("WARNING: No Luau offsets or AOB patterns configured yet.");
    eclipse_log("Script execution will be unavailable until offsets are provided.");
    return -1;
}

/* ─── Script execution ──────────────────────────────────────────────── */

static int execute_script(const char *script) {
    if (!f_luau_load || !f_lua_pcall || !g_lua_state) {
        eclipse_log("Cannot execute: Luau functions not resolved or lua_State is NULL.");
        print_chat("[Eclipse] Execution not available — offsets not set.");
        return -1;
    }

    eclipse_log("Executing script (%zu bytes)...", strlen(script));

    int load_result = f_luau_load(g_lua_state, "=Eclipse", script, strlen(script), 0);
    if (load_result != 0) {
        /* Get error message from the stack */
        if (f_lua_tolstring) {
            const char *err = f_lua_tolstring(g_lua_state, -1, NULL);
            eclipse_log("Load error: %s", err ? err : "(unknown)");
            if (err) {
                char msg[256];
                snprintf(msg, sizeof(msg), "[Eclipse] Load error: %.200s", err);
                print_chat(msg);
            }
        }
        if (f_lua_settop) f_lua_settop(g_lua_state, -2); /* pop error */
        return -1;
    }

    int pcall_result = f_lua_pcall(g_lua_state, 0, 0, 0);
    if (pcall_result != 0) {
        if (f_lua_tolstring) {
            const char *err = f_lua_tolstring(g_lua_state, -1, NULL);
            eclipse_log("Runtime error: %s", err ? err : "(unknown)");
            if (err) {
                char msg[256];
                snprintf(msg, sizeof(msg), "[Eclipse] Error: %.200s", err);
                print_chat(msg);
            }
        }
        if (f_lua_settop) f_lua_settop(g_lua_state, -2);
        return -1;
    }

    eclipse_log("Script executed successfully.");
    return 0;
}

/* ─── Load init.lua ─────────────────────────────────────────────────── */

static void load_init_lua(void) {
    /* Try multiple possible paths for init.lua */
    const char *paths[] = {
        INIT_LUA_PATH,
        "/tmp/eclipse_init.lua",
        NULL
    };

    for (int i = 0; paths[i]; i++) {
        FILE *f = fopen(paths[i], "rb");
        if (!f) continue;

        fseek(f, 0, SEEK_END);
        long len = ftell(f);
        rewind(f);

        char *buf = malloc(len + 1);
        if (!buf) { fclose(f); continue; }

        fread(buf, 1, len, f);
        buf[len] = '\0';
        fclose(f);

        eclipse_log("Loading init.lua from %s (%ld bytes)", paths[i], len);
        execute_script(buf);
        free(buf);
        return;
    }

    eclipse_log("init.lua not found in any search path.");
}

/* ─── Pipe listener thread ──────────────────────────────────────────── */

static void *pipe_listener_thread(void *arg) {
    (void)arg;

    eclipse_log("Pipe listener starting on %s", ECLIPSE_PIPE_PATH);

    /* Create the pipe if it doesn't exist */
    if (access(ECLIPSE_PIPE_PATH, F_OK) != 0) {
        if (mkfifo(ECLIPSE_PIPE_PATH, 0666) != 0 && errno != EEXIST) {
            eclipse_log("Failed to create pipe: %s", strerror(errno));
            return NULL;
        }
    }

    while (1) {
        /* Open pipe for reading (blocks until a writer connects) */
        int fd = open(ECLIPSE_PIPE_PATH, O_RDONLY);
        if (fd < 0) {
            eclipse_log("Pipe open error: %s", strerror(errno));
            sleep(1);
            continue;
        }

        /* Read protocol: [4 bytes length][data] */
        uint32_t script_len = 0;
        ssize_t r = read(fd, &script_len, sizeof(script_len));
        if (r != sizeof(script_len) || script_len == 0 || script_len > 10 * 1024 * 1024) {
            eclipse_log("Invalid packet header (read %zd, len=%u)", r, script_len);
            close(fd);
            continue;
        }

        char *script = malloc(script_len + 1);
        if (!script) {
            eclipse_log("OOM allocating %u bytes for script", script_len);
            close(fd);
            continue;
        }

        size_t total = 0;
        while (total < script_len) {
            r = read(fd, script + total, script_len - total);
            if (r <= 0) break;
            total += r;
        }
        script[total] = '\0';
        close(fd);

        if (total != script_len) {
            eclipse_log("Incomplete read: got %zu / %u", total, script_len);
            free(script);
            continue;
        }

        eclipse_log("Received script (%u bytes)", script_len);

        /* Execute the received script */
        if (f_luau_load && g_lua_state) {
            execute_script(script);
        } else {
            eclipse_log("Script received but execution engine not ready.");
            eclipse_log("Script preview: %.100s...", script);
            print_chat("[Eclipse] Received script — execution engine not ready.");
        }

        free(script);
    }

    return NULL;
}

/* ─── Constructor — runs when eclipse.so is loaded ──────────────────── */

__attribute__((constructor))
void eclipse_init(void) {
    eclipse_log("=== Eclipse Executor loaded ===");
    eclipse_log("PID: %d", getpid());

    print_chat("[Eclipse] Injected successfully!");

    /* Resolve Luau functions */
    int resolved = resolve_luau_functions();
    if (resolved == 0) {
        eclipse_log("Luau functions resolved — execution available.");
        print_chat("[Eclipse] Execution engine ready.");
        load_init_lua();
    } else {
        eclipse_log("Luau functions NOT resolved — pipe listener only.");
        print_chat("[Eclipse] Attached (execution pending offsets).");
    }

    /* Start pipe listener thread */
    pthread_t thread;
    if (pthread_create(&thread, NULL, pipe_listener_thread, NULL) != 0) {
        eclipse_log("Failed to create pipe listener thread!");
    } else {
        pthread_detach(thread);
        eclipse_log("Pipe listener thread started.");
    }
}

/* ─── Destructor ────────────────────────────────────────────────────── */

__attribute__((destructor))
void eclipse_cleanup(void) {
    eclipse_log("Eclipse unloading.");
    if (logfile) {
        fclose(logfile);
        logfile = NULL;
    }
}
