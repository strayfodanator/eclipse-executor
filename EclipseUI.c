#define _GNU_SOURCE
#include <gtk/gtk.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <pthread.h>
#include <glib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#define ECLIPSE_PIPE_PATH "/tmp/eclipse_pipe"

static GtkWidget *main_window;
static GtkWidget *editor;
static GtkWidget *status_label;
static gboolean attached = FALSE;

/* ─── CSS Theme ─────────────────────────────────────────────────────── */

static const char *css_data =
    "window {"
    "  background-color: #1a1a2e;"
    "}"
    "textview {"
    "  background-color: #16213e;"
    "  color: #e0e0e0;"
    "  font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;"
    "  font-size: 13px;"
    "  border-radius: 8px;"
    "  padding: 8px;"
    "}"
    "textview text {"
    "  background-color: #16213e;"
    "  color: #e0e0e0;"
    "}"
    "button {"
    "  background-color: #0f3460;"
    "  color: #e0e0e0;"
    "  border: 1px solid #533483;"
    "  border-radius: 6px;"
    "  padding: 6px 16px;"
    "  font-weight: bold;"
    "  font-size: 12px;"
    "  min-height: 32px;"
    "}"
    "button:hover {"
    "  background-color: #533483;"
    "  border-color: #e94560;"
    "}"
    "button:active {"
    "  background-color: #e94560;"
    "}"
    "#btn-execute {"
    "  background-color: #e94560;"
    "  border-color: #e94560;"
    "}"
    "#btn-execute:hover {"
    "  background-color: #c73e54;"
    "}"
    "#btn-attach {"
    "  background-color: #533483;"
    "  border-color: #533483;"
    "}"
    "#btn-attach:hover {"
    "  background-color: #6a42a0;"
    "}"
    ".status-bar {"
    "  background-color: #0f3460;"
    "  color: #7f8c8d;"
    "  font-size: 11px;"
    "  padding: 4px 10px;"
    "  border-radius: 0 0 8px 8px;"
    "}"
    ".title-bar {"
    "  color: #e94560;"
    "  font-size: 16px;"
    "  font-weight: bold;"
    "  padding: 8px;"
    "}";

/* ─── Utility ───────────────────────────────────────────────────────── */

pid_t findPID(const char *target_name) {
    DIR* d = opendir("/proc");
    if (!d) {
        g_printerr("[Eclipse] Error: Could not open /proc directory.\n");
        return -1;
    }

    struct dirent* e;
    while ((e = readdir(d))) {
        if (e->d_type != DT_DIR) continue;

        pid_t pid = atoi(e->d_name);
        if (pid <= 0) continue;

        char exe_path[PATH_MAX];
        char link_target[PATH_MAX];
        snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);

        ssize_t len = readlink(exe_path, link_target, sizeof(link_target) - 1);
        if (len == -1) continue;
        link_target[len] = '\0';

        if (strstr(link_target, target_name)) {
            closedir(d);
            return pid;
        }
    }
    closedir(d);
    g_printerr("[Eclipse] Error: Process '%s' not found.\n", target_name);
    return -1;
}

char* load_file_to_string(const char *filename) {
    FILE *f = fopen(filename, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long length = ftell(f);
    rewind(f);
    char *buffer = malloc(length + 1);
    if (!buffer) {
        fclose(f);
        return NULL;
    }
    fread(buffer, 1, length, f);
    buffer[length] = '\0';
    fclose(f);
    return buffer;
}

/* ─── Status helpers ────────────────────────────────────────────────── */

static gboolean set_status_idle(gpointer data) {
    char *msg = (char *)data;
    gtk_label_set_text(GTK_LABEL(status_label), msg);
    g_free(msg);
    return G_SOURCE_REMOVE;
}

static void set_status(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    char *msg = g_strdup_vprintf(fmt, args);
    va_end(args);
    g_idle_add(set_status_idle, msg);
}

/* ─── IPC: send script via named pipe ───────────────────────────────── */

static gboolean send_script_to_pipe(const char *script) {
    /* Create the pipe if it doesn't exist */
    if (access(ECLIPSE_PIPE_PATH, F_OK) != 0) {
        if (mkfifo(ECLIPSE_PIPE_PATH, 0666) != 0 && errno != EEXIST) {
            g_printerr("[Eclipse] Failed to create pipe: %s\n", strerror(errno));
            return FALSE;
        }
    }

    /* Open as non-blocking first to check if there is a reader */
    int fd = open(ECLIPSE_PIPE_PATH, O_WRONLY | O_NONBLOCK);
    if (fd < 0) {
        if (errno == ENXIO) {
            g_printerr("[Eclipse] No reader on pipe — is the library injected?\n");
        } else {
            g_printerr("[Eclipse] Pipe open error: %s\n", strerror(errno));
        }
        return FALSE;
    }

    /* Write: [4 bytes length][script data] */
    uint32_t len = (uint32_t)strlen(script);
    ssize_t w1 = write(fd, &len, sizeof(len));
    ssize_t w2 = write(fd, script, len);
    close(fd);

    if (w1 < 0 || w2 < 0) {
        g_printerr("[Eclipse] Pipe write error: %s\n", strerror(errno));
        return FALSE;
    }

    return TRUE;
}

/* ─── Button callbacks ──────────────────────────────────────────────── */

static void on_execute_clicked(GtkButton *button, gpointer user_data) {
    (void)button; (void)user_data;

    if (!attached) {
        set_status("⚠ Not attached — click Attach first.");
        return;
    }

    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(editor));
    GtkTextIter start, end;
    gtk_text_buffer_get_start_iter(buffer, &start);
    gtk_text_buffer_get_end_iter(buffer, &end);
    gchar *text = gtk_text_buffer_get_text(buffer, &start, &end, FALSE);

    if (strlen(text) == 0) {
        set_status("⚠ Editor is empty.");
        g_free(text);
        return;
    }

    g_print("[Eclipse] Sending script (%zu bytes)...\n", strlen(text));

    if (send_script_to_pipe(text)) {
        set_status("✓ Script sent (%zu bytes).", strlen(text));
    } else {
        set_status("✗ Failed to send — is the library injected?");
    }

    g_free(text);
}

static void on_clear_clicked(GtkButton *button, gpointer user_data) {
    (void)button; (void)user_data;
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(editor));
    gtk_text_buffer_set_text(buffer, "", -1);
    set_status("Editor cleared.");
}

/* ─── File open/save ────────────────────────────────────────────────── */

static void open_file_response(GObject *source_object, GAsyncResult *res, gpointer user_data) {
    (void)user_data;
    GtkFileDialog *dialog = GTK_FILE_DIALOG(source_object);
    GFile *file = gtk_file_dialog_open_finish(dialog, res, NULL);
    if (file) {
        char *filename = g_file_get_path(file);
        if (filename) {
            char *content = load_file_to_string(filename);
            if (content) {
                GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(editor));
                gtk_text_buffer_set_text(buffer, content, -1);
                set_status("Opened: %s", filename);
                free(content);
            }
            g_free(filename);
        }
        g_object_unref(file);
    }
}

static void on_open_file_clicked(GtkButton *button, gpointer user_data) {
    (void)button; (void)user_data;
    GtkFileDialog *dialog = gtk_file_dialog_new();
    gtk_file_dialog_set_title(dialog, "Open Script");
    gtk_file_dialog_open(dialog, GTK_WINDOW(main_window), NULL, open_file_response, NULL);
}

static void save_file_response(GObject *source_object, GAsyncResult *res, gpointer user_data) {
    (void)user_data;
    GtkFileDialog *dialog = GTK_FILE_DIALOG(source_object);
    GFile *file = gtk_file_dialog_save_finish(dialog, res, NULL);
    if (file) {
        char *filename = g_file_get_path(file);
        if (filename) {
            GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(editor));
            GtkTextIter start, end;
            gtk_text_buffer_get_start_iter(buffer, &start);
            gtk_text_buffer_get_end_iter(buffer, &end);
            gchar *text = gtk_text_buffer_get_text(buffer, &start, &end, FALSE);
            FILE *f = fopen(filename, "w");
            if (f) {
                fwrite(text, 1, strlen(text), f);
                fclose(f);
                set_status("Saved: %s", filename);
            }
            g_free(text);
            g_free(filename);
        }
        g_object_unref(file);
    }
}

static void on_save_file_clicked(GtkButton *button, gpointer user_data) {
    (void)button; (void)user_data;
    GtkFileDialog *dialog = gtk_file_dialog_new();
    gtk_file_dialog_set_title(dialog, "Save Script");
    gtk_file_dialog_save(dialog, GTK_WINDOW(main_window), NULL, save_file_response, NULL);
}

/* ─── Attach logic ──────────────────────────────────────────────────── */

struct attach_data {
    GtkButton *button;
};

struct label_update_data {
    GtkButton *button;
    char *new_label;
};

static gboolean update_button_label(gpointer user_data) {
    struct label_update_data *data = user_data;
    gtk_button_set_label(data->button, data->new_label);
    g_free(data->new_label);
    g_free(data);
    return G_SOURCE_REMOVE;
}

static void* attach_thread_func(void *arg) {
    struct attach_data *data = arg;
    const char* so_path = "./eclipse.so";
    const char* injector_path = "./injector";

    pid_t pid = findPID("sober");
    if (pid == -1) {
        struct label_update_data *upd = g_new(struct label_update_data, 1);
        upd->button = data->button;
        upd->new_label = g_strdup("Attach (Not Found)");
        g_idle_add(update_button_label, upd);
        set_status("✗ Sober process not found.");
        g_free(data);
        return NULL;
    }

    set_status("Attaching to PID %d...", pid);
    g_print("[Eclipse] Attempting to run injector for PID %d with library %s\n", pid, so_path);

    /* Create the named pipe before injection so the library has something to open */
    if (access(ECLIPSE_PIPE_PATH, F_OK) != 0) {
        mkfifo(ECLIPSE_PIPE_PATH, 0666);
    }

    gchar *stdout_buf = NULL;
    gchar *stderr_buf = NULL;
    gint exit_status = 0;
    GError *error = NULL;

    gchar *pid_str = g_strdup_printf("%d", pid);
    gchar *argv[] = { (gchar*)injector_path, pid_str, (gchar*)so_path, NULL };

    gboolean success = g_spawn_sync(
        NULL, argv, NULL,
        G_SPAWN_SEARCH_PATH,
        NULL, NULL,
        &stdout_buf, &stderr_buf,
        &exit_status, &error
    );

    g_free(pid_str);

    if (error) {
        g_printerr("[Eclipse] Error running injector: %s\n", error->message);
        g_error_free(error);
        struct label_update_data *upd = g_new(struct label_update_data, 1);
        upd->button = data->button;
        upd->new_label = g_strdup("Attach (Exec Error)");
        g_idle_add(update_button_label, upd);
        set_status("✗ Could not run injector binary.");
        g_free(data);
        return NULL;
    }

    if (!success || exit_status != 0) {
        g_printerr("[Eclipse] Injector failed. Exit status: %d\n", exit_status);
        if (stdout_buf) g_print("stdout: %s\n", stdout_buf);
        if (stderr_buf) g_printerr("stderr: %s\n", stderr_buf);
        struct label_update_data *upd = g_new(struct label_update_data, 1);
        upd->button = data->button;
        upd->new_label = g_strdup("Attach (Failed)");
        g_idle_add(update_button_label, upd);
        set_status("✗ Injection failed (exit %d).", exit_status);
        g_free(data);
        g_free(stdout_buf);
        g_free(stderr_buf);
        return NULL;
    }

    g_print("[Eclipse] Injector ran successfully.\n");

    attached = TRUE;

    struct label_update_data *upd = g_new(struct label_update_data, 1);
    upd->button = data->button;
    upd->new_label = g_strdup("Attached ✓");
    g_idle_add(update_button_label, upd);
    set_status("✓ Attached to Sober (PID %d).", pid);

    g_free(data);
    g_free(stdout_buf);
    g_free(stderr_buf);
    return NULL;
}

static void on_attach_clicked(GtkButton *button, gpointer user_data) {
    (void)user_data;
    if (attached) {
        set_status("Already attached.");
        return;
    }
    gtk_button_set_label(button, "Attaching...");
    struct attach_data *data = g_malloc(sizeof(struct attach_data));
    data->button = button;
    pthread_t thread;
    pthread_create(&thread, NULL, attach_thread_func, data);
    pthread_detach(thread);
}

/* ─── Window layout ─────────────────────────────────────────────────── */

static void activate(GtkApplication *app, gpointer user_data) {
    (void)user_data;

    /* Apply CSS */
    GtkCssProvider *css = gtk_css_provider_new();
    gtk_css_provider_load_from_string(css, css_data);
    gtk_style_context_add_provider_for_display(
        gdk_display_get_default(),
        GTK_STYLE_PROVIDER(css),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION
    );

    /* Main window */
    main_window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(main_window), "Eclipse Executor");
    gtk_window_set_default_size(GTK_WINDOW(main_window), 820, 440);
    gtk_window_set_resizable(GTK_WINDOW(main_window), FALSE);

    /* Root vertical box */
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_margin_start(vbox, 12);
    gtk_widget_set_margin_end(vbox, 12);
    gtk_widget_set_margin_top(vbox, 8);
    gtk_widget_set_margin_bottom(vbox, 8);
    gtk_window_set_child(GTK_WINDOW(main_window), vbox);

    /* Title */
    GtkWidget *title = gtk_label_new("🌑 Eclipse");
    gtk_widget_add_css_class(title, "title-bar");
    gtk_widget_set_halign(title, GTK_ALIGN_START);
    gtk_box_append(GTK_BOX(vbox), title);

    /* Editor with scrolled window */
    GtkWidget *scrolled = gtk_scrolled_window_new();
    gtk_widget_set_vexpand(scrolled, TRUE);
    gtk_widget_set_hexpand(scrolled, TRUE);
    gtk_box_append(GTK_BOX(vbox), scrolled);

    editor = gtk_text_view_new();
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(editor), TRUE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(editor), GTK_WRAP_WORD_CHAR);
    gtk_text_view_set_left_margin(GTK_TEXT_VIEW(editor), 8);
    gtk_text_view_set_top_margin(GTK_TEXT_VIEW(editor), 8);

    /* Set placeholder text */
    GtkTextBuffer *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(editor));
    gtk_text_buffer_set_text(buf, "-- Eclipse Executor\n-- Type your Lua script here\n", -1);

    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled), editor);

    /* Button bar */
    GtkWidget *button_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_margin_top(button_box, 8);
    gtk_widget_set_margin_bottom(button_box, 4);
    gtk_box_append(GTK_BOX(vbox), button_box);

    GtkWidget *btn_execute = gtk_button_new_with_label("▶ Execute");
    GtkWidget *btn_clear   = gtk_button_new_with_label("✕ Clear");
    GtkWidget *btn_open    = gtk_button_new_with_label("📂 Open");
    GtkWidget *btn_save    = gtk_button_new_with_label("💾 Save");
    GtkWidget *btn_attach  = gtk_button_new_with_label("⚡ Attach");

    gtk_widget_set_name(btn_execute, "btn-execute");
    gtk_widget_set_name(btn_attach, "btn-attach");

    gtk_box_append(GTK_BOX(button_box), btn_execute);
    gtk_box_append(GTK_BOX(button_box), btn_clear);
    gtk_box_append(GTK_BOX(button_box), btn_open);
    gtk_box_append(GTK_BOX(button_box), btn_save);

    /* Push attach button to the right */
    GtkWidget *spacer = gtk_label_new("");
    gtk_widget_set_hexpand(spacer, TRUE);
    gtk_box_append(GTK_BOX(button_box), spacer);
    gtk_box_append(GTK_BOX(button_box), btn_attach);

    /* Status bar */
    status_label = gtk_label_new("Ready — not attached.");
    gtk_widget_add_css_class(status_label, "status-bar");
    gtk_widget_set_halign(status_label, GTK_ALIGN_START);
    gtk_box_append(GTK_BOX(vbox), status_label);

    /* Connect signals */
    g_signal_connect(btn_execute, "clicked", G_CALLBACK(on_execute_clicked), NULL);
    g_signal_connect(btn_clear,   "clicked", G_CALLBACK(on_clear_clicked),   NULL);
    g_signal_connect(btn_open,    "clicked", G_CALLBACK(on_open_file_clicked), NULL);
    g_signal_connect(btn_save,    "clicked", G_CALLBACK(on_save_file_clicked), NULL);
    g_signal_connect(btn_attach,  "clicked", G_CALLBACK(on_attach_clicked),  NULL);

    gtk_window_present(GTK_WINDOW(main_window));
}

/* ─── Main ──────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
    GtkApplication *app;
    int status;

    app = gtk_application_new("com.eclipse.executor", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);
    status = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);

    return status;
}
