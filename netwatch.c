// netwatch.c - Monitor połączeń sieciowych z półprzezroczystym overlay
// Wykorzystuje: eBPF, memfd_create, mmap, mlock, pthread, GTK3
// Kompilacja: make
// Uruchomienie: sudo ./netwatch [opcje]
//
// Wersja: 1.1 - dodany filtr kierunku ruchu (IN/OUT/BOTH)

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <gtk/gtk.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define MAX_LOGS 100
#define OVERLAY_WIDTH 600
#define OVERLAY_HEIGHT 450

// ===== Struktura zdarzenia (MUSI być identyczna jak w netwatch.bpf.c) =====
struct conn_event {
    uint32_t pid;
    uint32_t uid;
    uint32_t saddr;
    uint32_t daddr;
    uint16_t sport;
    uint16_t dport;
    uint8_t  protocol;
    uint8_t  direction;
    uint8_t  severity;
    char     comm[16];
    uint64_t ts;
} __attribute__((packed));

// ===== Bufor logów =====
struct log_entry {
    struct conn_event event;
    char message[256];
    time_t timestamp;
    int valid;
};

static struct log_entry g_logs[MAX_LOGS];
static int g_log_head = 0;
static int g_log_count = 0;
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;

// ===== Globalne =====
static GtkWidget *g_overlay_window = NULL;
static GtkTextBuffer *g_text_buffer = NULL;
static volatile int g_running = 1;
static int g_debug = 1;

// ===== Filtrowanie po kierunku =====
typedef enum {
    FILTER_BOTH = 0,
    FILTER_IN = 1,
    FILTER_OUT = 2
} filter_mode_t;

static filter_mode_t g_filter = FILTER_BOTH;
static GtkWidget *g_btn_in = NULL;
static GtkWidget *g_btn_out = NULL;
static GtkWidget *g_btn_both = NULL;
static GtkWidget *g_status_label = NULL;

// Statystyki
static int g_stats_in = 0;
static int g_stats_out = 0;
static int g_stats_filtered = 0;

// ===== Wrappery na nowoczesne syscalle =====
static inline int sys_pidfd_open(pid_t pid, unsigned int flags) {
    return syscall(SYS_pidfd_open, pid, flags);
}

static inline int sys_pidfd_send_signal(int pidfd, int sig,
                                         siginfo_t *info,
                                         unsigned int flags) {
    return syscall(SYS_pidfd_send_signal, pidfd, sig, info, flags);
}

// ===== Formatowanie IPv4 =====
static void format_ip(uint32_t ip, char *buf, size_t len) {
    struct in_addr addr = { .s_addr = ip };
    if (!inet_ntop(AF_INET, &addr, buf, len)) {
        snprintf(buf, len, "?.?.?.?");
    }
}

// ===== Sprawdzenie czy IP jest "ciekawe" =====
static int is_interesting_ip(uint32_t ip) {
    uint8_t a = (ip >> 0) & 0xFF;
    if (a == 127) return 0;  // localhost
    if (ip == 0) return 0;   // 0.0.0.0
    return 1;
}

// ===== Sprawdź czy event pasuje do filtra kierunku =====
static int passes_filter(struct conn_event *evt) {
    switch (g_filter) {
        case FILTER_IN:
            return evt->direction == 0;
        case FILTER_OUT:
            return evt->direction == 1;
        case FILTER_BOTH:
        default:
            return 1;
    }
}

// ===== Dodanie wpisu do logu =====
static void add_log(struct conn_event *evt) {
    if (!evt) return;

    pthread_mutex_lock(&g_log_mutex);

    int idx = g_log_head;
    g_logs[idx].event = *evt;
    g_logs[idx].timestamp = time(NULL);
    g_logs[idx].valid = 1;

    char saddr_str[INET_ADDRSTRLEN];
    char daddr_str[INET_ADDRSTRLEN];
    format_ip(evt->saddr, saddr_str, sizeof(saddr_str));
    format_ip(evt->daddr, daddr_str, sizeof(daddr_str));

    const char *sev_str[] = { "INFO", "WARN", "CRIT" };
    const char *dir_str[] = { "IN ", "OUT" };

    int sev = (evt->severity <= 2) ? evt->severity : 0;
    int dir = (evt->direction <= 1) ? evt->direction : 0;

    char safe_comm[17];
    memcpy(safe_comm, evt->comm, 16);
    safe_comm[16] = '\0';

    snprintf(g_logs[idx].message, sizeof(g_logs[idx].message),
        "[%s] %s %s:%u -> %s:%u (pid=%u %s)",
        sev_str[sev], dir_str[dir],
        saddr_str, evt->sport,
        daddr_str, evt->dport,
        evt->pid, safe_comm);

    g_log_head = (g_log_head + 1) % MAX_LOGS;
    if (g_log_count < MAX_LOGS) g_log_count++;

    pthread_mutex_unlock(&g_log_mutex);

    if (g_debug) {
        fprintf(stderr, "[LOG] %s\n", g_logs[idx].message);
    }
}

// ===== Aktualizacja okna overlay =====
static gboolean update_overlay(gpointer data) {
    (void)data;
    if (!g_text_buffer) return TRUE;

    // Aktualizuj label statusu
    if (g_status_label) {
        const char *filter_str[] = {"BOTH", "IN only", "OUT only"};
        char status[256];
        snprintf(status, sizeof(status),
            "Filter: %s | IN: %d | OUT: %d | Filtered: %d",
            filter_str[g_filter],
            g_stats_in, g_stats_out, g_stats_filtered);
        gtk_label_set_text(GTK_LABEL(g_status_label), status);
    }

    pthread_mutex_lock(&g_log_mutex);

    GtkTextIter start, end;
    gtk_text_buffer_get_bounds(g_text_buffer, &start, &end);
    gtk_text_buffer_delete(g_text_buffer, &start, &end);

    if (g_log_count == 0) {
        gtk_text_buffer_get_end_iter(g_text_buffer, &end);
        gtk_text_buffer_insert_with_tags_by_name(g_text_buffer, &end,
            "NetWatch - oczekiwanie na polaczenia...\n",
            -1, "info", NULL);
        pthread_mutex_unlock(&g_log_mutex);
        return TRUE;
    }

    int show = (g_log_count < 20) ? g_log_count : 20;
    int start_idx = g_log_head - show;
    if (start_idx < 0) start_idx += MAX_LOGS;

    for (int i = 0; i < show; i++) {
        int idx = (start_idx + i) % MAX_LOGS;
        if (!g_logs[idx].valid) continue;

        const char *tag = "info";
        switch (g_logs[idx].event.severity) {
            case 2: tag = "critical"; break;
            case 1: tag = "warning"; break;
            default: tag = "info"; break;
        }

        struct tm tm_result;
        struct tm *tm = localtime_r(&g_logs[idx].timestamp, &tm_result);
        char timebuf[16];
        if (tm) {
            strftime(timebuf, sizeof(timebuf), "%H:%M:%S", tm);
        } else {
            strcpy(timebuf, "??:??:??");
        }

        char line[600];
        snprintf(line, sizeof(line), "%s %s\n",
                 timebuf, g_logs[idx].message);

        gtk_text_buffer_get_end_iter(g_text_buffer, &end);
        gtk_text_buffer_insert_with_tags_by_name(g_text_buffer, &end,
            line, -1, tag, NULL);
    }

    pthread_mutex_unlock(&g_log_mutex);
    return TRUE;
}

// ===== Callback'i przycisków filtrowania =====
static void on_filter_changed(filter_mode_t new_filter) {
    g_filter = new_filter;

    const char *mode_str[] = {"BOTH", "IN", "OUT"};
    if (g_debug) {
        fprintf(stderr, "[FILTER] Changed to: %s\n", mode_str[new_filter]);
    }

    // Aktualizuj wygląd przycisków
    GtkStyleContext *ctx;

    if (g_btn_both) {
        ctx = gtk_widget_get_style_context(g_btn_both);
        if (new_filter == FILTER_BOTH)
            gtk_style_context_add_class(ctx, "filter-active");
        else
            gtk_style_context_remove_class(ctx, "filter-active");
    }

    if (g_btn_in) {
        ctx = gtk_widget_get_style_context(g_btn_in);
        if (new_filter == FILTER_IN)
            gtk_style_context_add_class(ctx, "filter-active");
        else
            gtk_style_context_remove_class(ctx, "filter-active");
    }

    if (g_btn_out) {
        ctx = gtk_widget_get_style_context(g_btn_out);
        if (new_filter == FILTER_OUT)
            gtk_style_context_add_class(ctx, "filter-active");
        else
            gtk_style_context_remove_class(ctx, "filter-active");
    }
}

static void on_btn_both_clicked(GtkButton *btn, gpointer data) {
    (void)btn; (void)data;
    on_filter_changed(FILTER_BOTH);
}

static void on_btn_in_clicked(GtkButton *btn, gpointer data) {
    (void)btn; (void)data;
    on_filter_changed(FILTER_IN);
}

static void on_btn_out_clicked(GtkButton *btn, gpointer data) {
    (void)btn; (void)data;
    on_filter_changed(FILTER_OUT);
}

// ===== Skróty klawiszowe =====
static gboolean on_key_press(GtkWidget *widget, GdkEventKey *event, gpointer data) {
    (void)widget; (void)data;

    switch (event->keyval) {
        case GDK_KEY_1:
            on_filter_changed(FILTER_BOTH);
            return TRUE;
        case GDK_KEY_2:
            on_filter_changed(FILTER_IN);
            return TRUE;
        case GDK_KEY_3:
            on_filter_changed(FILTER_OUT);
            return TRUE;
        case GDK_KEY_q:
        case GDK_KEY_Q:
            g_running = 0;
            gtk_main_quit();
            return TRUE;
    }
    return FALSE;
}

// ===== Tworzenie półprzezroczystego okna overlay =====
static void create_overlay_window(void) {
    g_overlay_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(g_overlay_window), "NetWatch");
    gtk_window_set_default_size(GTK_WINDOW(g_overlay_window),
                                 OVERLAY_WIDTH, OVERLAY_HEIGHT);

    gtk_window_set_keep_above(GTK_WINDOW(g_overlay_window), TRUE);
    gtk_window_set_decorated(GTK_WINDOW(g_overlay_window), FALSE);
    gtk_window_set_skip_taskbar_hint(GTK_WINDOW(g_overlay_window), TRUE);
    gtk_window_set_skip_pager_hint(GTK_WINDOW(g_overlay_window), TRUE);

    // WAŻNE: musi akceptować focus żeby działały skróty klawiszowe i przyciski
    gtk_window_set_accept_focus(GTK_WINDOW(g_overlay_window), TRUE);
    gtk_window_set_type_hint(GTK_WINDOW(g_overlay_window),
                              GDK_WINDOW_TYPE_HINT_NORMAL);

    GdkScreen *screen = gtk_widget_get_screen(g_overlay_window);
    GdkVisual *visual = gdk_screen_get_rgba_visual(screen);
    if (visual && gdk_screen_is_composited(screen)) {
        gtk_widget_set_visual(g_overlay_window, visual);
    }
    gtk_widget_set_app_paintable(g_overlay_window, TRUE);
    gtk_widget_set_opacity(g_overlay_window, 0.88);

    GdkRectangle workarea;
    GdkDisplay *display = gdk_display_get_default();
    GdkMonitor *monitor = gdk_display_get_primary_monitor(display);
    if (monitor) {
        gdk_monitor_get_workarea(monitor, &workarea);
        gtk_window_move(GTK_WINDOW(g_overlay_window),
                        workarea.width - OVERLAY_WIDTH - 20, 50);
    } else {
        gtk_window_move(GTK_WINDOW(g_overlay_window), 1200, 50);
    }

    // CSS - z stylami dla przycisków
    GtkCssProvider *css = gtk_css_provider_new();
    const char *css_data =
        "window {"
        "  background-color: rgba(15, 15, 25, 0.85);"
        "  border: 1px solid rgba(100, 100, 120, 0.5);"
        "  border-radius: 8px;"
        "}"
        "textview {"
        "  background-color: transparent;"
        "  color: white;"
        "  font-family: 'DejaVu Sans Mono', monospace;"
        "  font-size: 10pt;"
        "  padding: 12px;"
        "}"
        "textview text { background-color: transparent; }"
        "scrolledwindow { background-color: transparent; }"
        "button {"
        "  background: rgba(40, 40, 60, 0.8);"
        "  color: #aaaaaa;"
        "  border: 1px solid rgba(80, 80, 100, 0.5);"
        "  border-radius: 4px;"
        "  padding: 4px 12px;"
        "  margin: 2px;"
        "  font-weight: normal;"
        "  font-family: 'DejaVu Sans Mono', monospace;"
        "  font-size: 9pt;"
        "}"
        "button:hover {"
        "  background: rgba(60, 60, 90, 0.9);"
        "  color: white;"
        "}"
        "button.filter-active {"
        "  background: rgba(80, 120, 200, 0.9);"
        "  color: white;"
        "  font-weight: bold;"
        "  border: 1px solid rgba(120, 160, 240, 0.8);"
        "}"
        "label {"
        "  color: #cccccc;"
        "  font-family: 'DejaVu Sans Mono', monospace;"
        "  font-size: 9pt;"
        "  padding: 4px 8px;"
        "}";

    gtk_css_provider_load_from_data(css, css_data, -1, NULL);
    gtk_style_context_add_provider_for_screen(
        gdk_screen_get_default(),
        GTK_STYLE_PROVIDER(css),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(css);

    // Główny kontener pionowy
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);

    // === Pasek przycisków na górze ===
    GtkWidget *button_bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_widget_set_halign(button_bar, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_top(button_bar, 6);
    gtk_widget_set_margin_bottom(button_bar, 4);

    g_btn_both = gtk_button_new_with_label("[1] BOTH");
    g_btn_in = gtk_button_new_with_label("[2] IN only");
    g_btn_out = gtk_button_new_with_label("[3] OUT only");

    g_signal_connect(g_btn_both, "clicked", G_CALLBACK(on_btn_both_clicked), NULL);
    g_signal_connect(g_btn_in, "clicked", G_CALLBACK(on_btn_in_clicked), NULL);
    g_signal_connect(g_btn_out, "clicked", G_CALLBACK(on_btn_out_clicked), NULL);

    gtk_box_pack_start(GTK_BOX(button_bar), g_btn_both, FALSE, FALSE, 2);
    gtk_box_pack_start(GTK_BOX(button_bar), g_btn_in, FALSE, FALSE, 2);
    gtk_box_pack_start(GTK_BOX(button_bar), g_btn_out, FALSE, FALSE, 2);

    // === Status label ===
    g_status_label = gtk_label_new("Filter: BOTH | IN: 0 | OUT: 0 | Filtered: 0");
    gtk_widget_set_halign(g_status_label, GTK_ALIGN_START);

    // === Widok tekstu ===
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
        GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);

    GtkWidget *view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(view), GTK_WRAP_WORD_CHAR);

    g_text_buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(view));

    gtk_text_buffer_create_tag(g_text_buffer, "critical",
        "foreground", "#ff5555",
        "weight", PANGO_WEIGHT_BOLD, NULL);
    gtk_text_buffer_create_tag(g_text_buffer, "warning",
        "foreground", "#ffaa00", NULL);
    gtk_text_buffer_create_tag(g_text_buffer, "info",
        "foreground", "#88ff88", NULL);

    gtk_container_add(GTK_CONTAINER(scroll), view);

    // Złożenie wszystkiego
    gtk_box_pack_start(GTK_BOX(vbox), button_bar, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), g_status_label, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), scroll, TRUE, TRUE, 0);

    gtk_container_add(GTK_CONTAINER(g_overlay_window), vbox);

    // Skróty klawiszowe
    g_signal_connect(g_overlay_window, "key-press-event",
                     G_CALLBACK(on_key_press), NULL);

    g_timeout_add(200, update_overlay, NULL);
    gtk_widget_show_all(g_overlay_window);

    // Ustaw początkowy stan przycisków
    on_filter_changed(g_filter);
}

// ===== Callback eBPF perf event =====
static void handle_event(void *ctx, int cpu, void *data, __u32 size) {
    (void)ctx;

    if (g_debug) {
        fprintf(stderr, "[BPF] event from cpu=%d size=%u (expected=%zu)\n",
                cpu, size, sizeof(struct conn_event));
    }

    if (size < sizeof(struct conn_event)) {
        fprintf(stderr, "[BPF] WARNING: event smaller than expected\n");
        return;
    }

    struct conn_event *evt = (struct conn_event *)data;

    if (g_debug) {
        char safe_comm[17];
        memcpy(safe_comm, evt->comm, 16);
        safe_comm[16] = '\0';

        fprintf(stderr, "[BPF] pid=%u uid=%u comm='%s' "
                "saddr=0x%08x daddr=0x%08x "
                "sport=%u dport=%u dir=%u sev=%u\n",
                evt->pid, evt->uid, safe_comm,
                evt->saddr, evt->daddr,
                evt->sport, evt->dport,
                evt->direction, evt->severity);
    }

    // Statystyki ZAWSZE liczone (przed filtrowaniem)
    if (evt->direction == 0) g_stats_in++;
    else g_stats_out++;

    // Filtr kierunku
    if (!passes_filter(evt)) {
        g_stats_filtered++;
        if (g_debug) {
            fprintf(stderr, "[BPF] filtered out by direction filter\n");
        }
        return;
    }

    // Filtr IP
    if (!is_interesting_ip(evt->daddr) && !is_interesting_ip(evt->saddr)) {
        if (g_debug) {
            fprintf(stderr, "[BPF] filtered (uninteresting IP)\n");
        }
        return;
    }

    add_log(evt);
}

static void handle_lost(void *ctx, int cpu, __u64 cnt) {
    (void)ctx;
    fprintf(stderr, "[BPF] Lost %llu events on CPU %d\n",
            (unsigned long long)cnt, cpu);
}

// ===== Wątek monitorujący eBPF =====
static void *monitor_thread(void *arg) {
    struct perf_buffer *pb = (struct perf_buffer *)arg;

    while (g_running) {
        int err = perf_buffer__poll(pb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "[BPF] perf_buffer__poll error: %d\n", err);
            break;
        }
    }

    return NULL;
}

// ===== Obsługa sygnałów =====
static void signal_handler(int sig) {
    (void)sig;
    fprintf(stderr, "\n[NetWatch] Otrzymano sygnał, kończę...\n");
    g_running = 0;
    gtk_main_quit();
}

// ===== Pomoc =====
static void print_help(const char *prog) {
    printf("Użycie: sudo %s [OPCJE]\n\n", prog);
    printf("NetWatch v1.1 - Monitor połączeń sieciowych z eBPF\n\n");
    printf("Opcje:\n");
    printf("  -q, --quiet          Wyłącz debug na stderr\n");
    printf("  -d, --direction DIR  Filtruj kierunek (in/out/both), domyślnie: both\n");
    printf("  -h, --help           Pokaż tę pomoc\n");
    printf("\nSkróty klawiszowe w oknie:\n");
    printf("  1  Pokazuj wszystkie (BOTH)\n");
    printf("  2  Tylko przychodzące (IN)\n");
    printf("  3  Tylko wychodzące (OUT)\n");
    printf("  Q  Zakończ program\n");
    printf("\nPrzykłady użycia:\n");
    printf("  sudo %s                  # Wszystkie połączenia\n", prog);
    printf("  sudo %s -d out           # Tylko wychodzące\n", prog);
    printf("  sudo %s -d in            # Tylko przychodzące\n", prog);
    printf("  sudo %s -d out -q        # Tylko wychodzące, cicho\n", prog);
}

// ===== MAIN =====
int main(int argc, char *argv[]) {
    if (geteuid() != 0) {
        fprintf(stderr, "BŁĄD: Program wymaga uprawnień root (eBPF)\n");
        fprintf(stderr, "Uruchom: sudo ./netwatch\n");
        return 1;
    }

    // Parsuj argumenty
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0) {
            g_debug = 0;
        }
        else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--direction") == 0) {
            if (i + 1 < argc) {
                i++;
                if (strcmp(argv[i], "in") == 0) {
                    g_filter = FILTER_IN;
                } else if (strcmp(argv[i], "out") == 0) {
                    g_filter = FILTER_OUT;
                } else if (strcmp(argv[i], "both") == 0) {
                    g_filter = FILTER_BOTH;
                } else {
                    fprintf(stderr, "Nieznany kierunek: %s (użyj: in/out/both)\n", argv[i]);
                    return 1;
                }
            } else {
                fprintf(stderr, "Brak wartości dla -d/--direction\n");
                return 1;
            }
        }
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_help(argv[0]);
            return 0;
        }
        else {
            fprintf(stderr, "Nieznana opcja: %s\n", argv[i]);
            fprintf(stderr, "Użyj --help dla pomocy\n");
            return 1;
        }
    }

    const char *filter_str[] = {"BOTH", "IN", "OUT"};
    printf("[NetWatch] sizeof(struct conn_event) = %zu bajtów\n",
           sizeof(struct conn_event));
    printf("[NetWatch] Filtr kierunku: %s\n", filter_str[g_filter]);

    gtk_init(&argc, &argv);
    memset(g_logs, 0, sizeof(g_logs));

    struct bpf_object *obj = bpf_object__open_file("netwatch.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "BŁĄD: Nie można otworzyć netwatch.bpf.o\n");
        fprintf(stderr, "Upewnij się że plik jest w bieżącym katalogu.\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "BŁĄD: Nie można załadować eBPF: %s\n",
                strerror(errno));
        return 1;
    }

    struct bpf_program *prog_out =
        bpf_object__find_program_by_name(obj, "trace_outbound_connect");
    struct bpf_program *prog_in =
        bpf_object__find_program_by_name(obj, "trace_inbound_accept");

    if (!prog_out) {
        fprintf(stderr, "BŁĄD: Nie znaleziono 'trace_outbound_connect'\n");
        return 1;
    }
    if (!prog_in) {
        fprintf(stderr, "BŁĄD: Nie znaleziono 'trace_inbound_accept'\n");
        return 1;
    }

    struct bpf_link *link_out = bpf_program__attach(prog_out);
    if (libbpf_get_error(link_out)) {
        fprintf(stderr, "BŁĄD: kprobe tcp_connect: %s\n",
                strerror(-libbpf_get_error(link_out)));
        return 1;
    }

    struct bpf_link *link_in = bpf_program__attach(prog_in);
    if (libbpf_get_error(link_in)) {
        fprintf(stderr, "BŁĄD: kretprobe inet_csk_accept: %s\n",
                strerror(-libbpf_get_error(link_in)));
        return 1;
    }

    printf("[NetWatch] eBPF aktywny:\n");
    printf("  - kprobe/tcp_connect (połączenia wychodzące)\n");
    printf("  - kretprobe/inet_csk_accept (połączenia przychodzące)\n");

    int map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (map_fd < 0) {
        fprintf(stderr, "BŁĄD: Nie znaleziono mapy 'events'\n");
        return 1;
    }

    struct perf_buffer *pb = perf_buffer__new(map_fd, 8,
        handle_event, handle_lost, NULL, NULL);

    if (libbpf_get_error(pb)) {
        fprintf(stderr, "BŁĄD: Nie można utworzyć perf buffer\n");
        return 1;
    }

    pthread_t monitor_tid;
    if (pthread_create(&monitor_tid, NULL, monitor_thread, pb) != 0) {
        fprintf(stderr, "BŁĄD: Nie można utworzyć wątku\n");
        return 1;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    create_overlay_window();

    printf("[NetWatch] Overlay aktywny - Ctrl+C aby zakończyć\n");
    printf("[NetWatch] Skróty: 1=BOTH, 2=IN, 3=OUT, Q=quit\n");
    printf("[NetWatch] Test: curl http://example.com\n\n");

    gtk_main();

    g_running = 0;
    pthread_join(monitor_tid, NULL);
    perf_buffer__free(pb);
    bpf_link__destroy(link_out);
    bpf_link__destroy(link_in);
    bpf_object__close(obj);

    printf("[NetWatch] Zakończono\n");
    return 0;
}
