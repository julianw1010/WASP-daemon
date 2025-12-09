#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <ctype.h>
#include <stdint.h>
#include <limits.h>
#include <sched.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <linux/perf_event.h>
#include <linux/mempolicy.h>
#include <asm/unistd.h>
#include <math.h>

/*
 * WASP: Workload-Aware Self-Replicating Page-Tables
 * TUI version with automatic steering matrix
 * 
 * Updated to work with Mitosis kernel module /proc interfaces
 */

// ============================================================================
// CONFIGURATION - Must match kernel's NUMA_NODE_COUNT in mm_types.h
// ============================================================================

#define NUMA_NODE_COUNT 8   /* Must match kernel definition */
#define MAX_NUMA_NODES  NUMA_NODE_COUNT
#define MAX_PROCS       256

#define PTL_ITERATIONS      10
#define PTL_UPDATE_INTERVAL 1000
#define PTL_PAGES           64

static double THR_MAR  = 10.0 * 1000000.0;
static double THR_DTLB = 0.01;
#define PF_SAMPLE_INTERVAL  1000

static int UPDATE_INTERVAL_MS = 1000;
static int HYSTERESIS_MS = 1000;

/* prctl commands - must match kernel's include/uapi/linux/prctl.h */
#ifndef PR_SET_PGTABLE_REPL
#define PR_SET_PGTABLE_REPL          100
#endif
#ifndef PR_GET_PGTABLE_REPL
#define PR_GET_PGTABLE_REPL          101
#endif
#ifndef PR_SET_PGTABLE_REPL_STEERING
#define PR_SET_PGTABLE_REPL_STEERING 104
#endif
#ifndef PR_GET_PGTABLE_REPL_STEERING
#define PR_GET_PGTABLE_REPL_STEERING 105
#endif

/* Mitosis proc paths */
#define MITOSIS_PROC_DIR     "/proc/mitosis"
#define MITOSIS_STATUS_PATH  MITOSIS_PROC_DIR "/status"
#define MITOSIS_ACTIVE_PATH  MITOSIS_PROC_DIR "/active"
#define MITOSIS_MODE_PATH    MITOSIS_PROC_DIR "/mode"
#define MITOSIS_INHERIT_PATH MITOSIS_PROC_DIR "/inherit"
#define MITOSIS_CACHE_PATH   MITOSIS_PROC_DIR "/cache"

// ============================================================================
// SYSTEM PROCESS BLACKLIST
// ============================================================================

static const char *SYSTEM_BLACKLIST[] = {
    "bash", "sh", "zsh", "fish", "csh", "tcsh", "ksh", "dash",
    "ssh", "sshd", "sftp", "scp",
    "login", "getty", "agetty",
    "systemd", "init", "launchd",
    "cron", "crond", "atd",
    "dbus", "dbus-daemon", "dbus-broker",
    "udev", "udevd", "systemd-udevd",
    "journald", "systemd-journald", "rsyslogd", "syslogd",
    "NetworkManager", "dhclient", "dhcpcd", "wpa_supplicant",
    "polkitd", "accounts-daemon",
    "sudo", "su", "pkexec",
    "tmux", "screen", "tmux:server",
    "vim", "nvim", "nano", "emacs", "vi",
    "less", "more", "cat", "grep", "awk", "sed",
    "top", "htop", "ps", "watch",
    "ls", "find", "xargs", "head", "tail",
    "waspd", "wasp",
    NULL
};

static int is_system_process(const char *name) {
    for (int i = 0; SYSTEM_BLACKLIST[i] != NULL; i++) {
        if (strcmp(name, SYSTEM_BLACKLIST[i]) == 0)
            return 1;
    }
    if (strncmp(name, "systemd-", 8) == 0) return 1;
    if (strncmp(name, "kworker", 7) == 0) return 1;
    if (strncmp(name, "ksoftirq", 8) == 0) return 1;
    if (strncmp(name, "migration", 9) == 0) return 1;
    if (strncmp(name, "rcu_", 4) == 0) return 1;
    return 0;
}

// ============================================================================
// ANSI ESCAPE CODES
// ============================================================================

#define ESC         "\033"
#define CLEAR       ESC "[2J"
#define HOME        ESC "[H"
#define HIDE_CUR    ESC "[?25l"
#define SHOW_CUR    ESC "[?25h"
#define ALT_BUF_ON  ESC "[?1049h"
#define ALT_BUF_OFF ESC "[?1049l"
#define BOLD        ESC "[1m"
#define DIM         ESC "[2m"
#define RESET       ESC "[0m"
#define GREEN       ESC "[32m"
#define YELLOW      ESC "[33m"
#define RED         ESC "[31m"
#define CYAN        ESC "[36m"
#define MAGENTA     ESC "[35m"
#define BG_BLUE     ESC "[44m"

#define GOTO(r,c)   printf(ESC "[%d;%dH", (r), (c))

// ============================================================================
// GLOBALS
// ============================================================================

volatile sig_atomic_t stop_requested = 0;
static pid_t daemon_pid = 0;
static double cpu_ghz = 2.8;
static int ptl_interval = PTL_UPDATE_INTERVAL;
static struct termios orig_termios;
static int term_rows = 24, term_cols = 80;

int num_online_nodes = 0;
int node_to_cpu_map[MAX_NUMA_NODES];
double ptl_matrix[MAX_NUMA_NODES][MAX_NUMA_NODES];
int steering_matrix[NUMA_NODE_COUNT];  /* Global steering: phys_node -> replica_node */
double last_ptl_update = 0;
double last_ptl_duration = 0;
int ptl_measuring = 0;

/* Mitosis kernel status */
int mitosis_available = 0;
int mitosis_mode = -1;       /* From /proc/mitosis/mode */
int mitosis_inherit = 1;     /* From /proc/mitosis/inherit */
size_t cache_total_pages = 0;
size_t cache_per_node[NUMA_NODE_COUNT];

// ============================================================================
// STRUCTURES
// ============================================================================

typedef struct {
    int fd;
    struct perf_event_attr pe;
} perf_counter_t;

typedef struct {
    pid_t tgid;
    char name[32];
    perf_counter_t mem_loads;
    perf_counter_t dtlb_walks;
    perf_counter_t dtlb_accesses;
    long long prev_mem_loads;
    long long prev_dtlb_walks;
    long long prev_dtlb_accesses;
    double last_sample_time;
    double last_mar;
    double last_dtlb_mr;
    int mitosis_enabled;
    long long prev_majflt;
    long long prev_minflt;
    double last_pf_sample_time;
    double last_pf_rate;
    int active;
    double above_threshold_since;
    double below_threshold_since;
} process_t;

process_t procs[MAX_PROCS];
int num_procs = 0;
int mitosis_count = 0;

// ============================================================================
// LOW-LEVEL HELPERS
// ============================================================================

static inline uint64_t rdtsc_fenced(void) {
    uint32_t lo, hi;
    asm volatile("lfence; rdtsc; lfence" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static inline void clflush(void *p) {
    asm volatile("clflush (%0)" :: "r"(p) : "memory");
}

static inline void mfence(void) {
    asm volatile("mfence" ::: "memory");
}

static long perf_event_open(struct perf_event_attr *attr, pid_t pid,
                            int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static long sys_mbind(void *start, unsigned long len, int mode,
                      const unsigned long *nmask, unsigned long maxnode, unsigned flags) {
    return syscall(__NR_mbind, start, len, mode, nmask, maxnode, flags);
}

static void detect_cpu_freq(void) {
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            double mhz;
            if (sscanf(line, "cpu MHz : %lf", &mhz) == 1) {
                cpu_ghz = mhz / 1000.0;
                fclose(f);
                return;
            }
        }
        fclose(f);
    }
}

static double get_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
}

// ============================================================================
// MITOSIS PROC INTERFACE
// ============================================================================

static int mitosis_check_available(void) {
    return access(MITOSIS_PROC_DIR, F_OK) == 0;
}

static int mitosis_read_int(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -999;
    int val = -999;
    if (fscanf(f, "%d", &val) != 1) val = -999;
    fclose(f);
    return val;
}

static int mitosis_write_int(const char *path, int val) {
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fprintf(f, "%d\n", val);
    fclose(f);
    return 0;
}

static void mitosis_read_cache_status(void) {
    cache_total_pages = 0;
    memset(cache_per_node, 0, sizeof(cache_per_node));
    
    FILE *f = fopen(MITOSIS_CACHE_PATH, "r");
    if (!f) return;
    
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        int node;
        size_t pages;
        if (sscanf(line, "  Node %d: %zu pages", &node, &pages) == 2) {
            if (node >= 0 && node < NUMA_NODE_COUNT) {
                cache_per_node[node] = pages;
                cache_total_pages += pages;
            }
        }
    }
    fclose(f);
}

static void mitosis_update_status(void) {
    if (!mitosis_available) {
        mitosis_available = mitosis_check_available();
    }
    
    if (mitosis_available) {
        mitosis_mode = mitosis_read_int(MITOSIS_MODE_PATH);
        mitosis_inherit = mitosis_read_int(MITOSIS_INHERIT_PATH);
        mitosis_read_cache_status();
    }
}

static int mitosis_set_mode(int mode) {
    return mitosis_write_int(MITOSIS_MODE_PATH, mode);
}

static int mitosis_set_inherit(int inherit) {
    return mitosis_write_int(MITOSIS_INHERIT_PATH, inherit);
}

static int mitosis_populate_cache(int pages_per_node) {
    return mitosis_write_int(MITOSIS_CACHE_PATH, pages_per_node);
}

static int mitosis_drain_cache(void) {
    return mitosis_write_int(MITOSIS_CACHE_PATH, -1);
}

// ============================================================================
// TERMINAL HANDLING
// ============================================================================

static void get_term_size(void) {
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
        term_rows = ws.ws_row;
        term_cols = ws.ws_col;
    }
}

static void term_init(void) {
    tcgetattr(STDIN_FILENO, &orig_termios);
    struct termios raw = orig_termios;
    raw.c_lflag &= ~(ECHO | ICANON);
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
    printf(ALT_BUF_ON HIDE_CUR CLEAR HOME);
    fflush(stdout);
}

static void term_restore(void) {
    printf(RESET SHOW_CUR ALT_BUF_OFF);
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
    fflush(stdout);
}

// ============================================================================
// TOPOLOGY
// ============================================================================

static int get_node_for_cpu(int cpu) {
    char path[128];
    for (int n = 0; n < MAX_NUMA_NODES; n++) {
        snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/node%d", cpu, n);
        if (access(path, F_OK) == 0) return n;
    }
    return 0;
}

static void init_topology(void) {
    int nodes_found = 0;
    for (int i = 0; i < MAX_NUMA_NODES; i++) {
        node_to_cpu_map[i] = -1;
        steering_matrix[i] = -1;  /* Default: auto (use local) */
        for (int j = 0; j < MAX_NUMA_NODES; j++)
            ptl_matrix[i][j] = 0;
        
        char path[64];
        snprintf(path, sizeof(path), "/sys/devices/system/node/node%d", i);
        if (access(path, F_OK) == 0) nodes_found++;
    }
    num_online_nodes = nodes_found;
    
    for (int cpu = 0; cpu < 1024; cpu++) {
        char path[128];
        snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d", cpu);
        if (access(path, F_OK) != 0) break;
        
        int node = get_node_for_cpu(cpu);
        if (node < MAX_NUMA_NODES && node_to_cpu_map[node] == -1)
            node_to_cpu_map[node] = cpu;
    }
}

// ============================================================================
// PTL MEASUREMENT & STEERING MATRIX COMPUTATION
// ============================================================================

static void compute_steering_matrix(void) {
    for (int phys = 0; phys < num_online_nodes && phys < NUMA_NODE_COUNT; phys++) {
        if (node_to_cpu_map[phys] == -1) {
            steering_matrix[phys] = -1;
            continue;
        }
        
        double best_latency = 1e18;
        int best_node = phys;
        
        for (int repl = 0; repl < num_online_nodes; repl++) {
            if (node_to_cpu_map[repl] == -1) continue;
            double lat = ptl_matrix[phys][repl];
            if (lat > 0 && lat < best_latency) {
                best_latency = lat;
                best_node = repl;
            }
        }
        
        steering_matrix[phys] = best_node;
    }
    
    /* Initialize remaining entries to -1 (auto) */
    for (int i = num_online_nodes; i < NUMA_NODE_COUNT; i++) {
        steering_matrix[i] = -1;
    }
}

static void update_ptl_matrix(void) {
    double now = get_time_ms();
    if (now - last_ptl_update < ptl_interval) return;
    last_ptl_update = now;
    ptl_measuring = 1;
    
    double start_time = get_time_ms();
    
    double (*results)[MAX_NUMA_NODES] = mmap(NULL, sizeof(double) * MAX_NUMA_NODES * MAX_NUMA_NODES,
                                              PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (results == MAP_FAILED) { ptl_measuring = 0; return; }
    
    pid_t pid = fork();
    if (pid == 0) {
        size_t buf_size = PTL_PAGES * 4096;
        
        char *bufs[MAX_NUMA_NODES] = {NULL};
        for (int d = 0; d < num_online_nodes; d++) {
            if (node_to_cpu_map[d] == -1) continue;
            void *buf = mmap(NULL, buf_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (buf == MAP_FAILED) continue;
            unsigned long nodemask = 1UL << d;
            if (sys_mbind(buf, buf_size, 2, &nodemask, MAX_NUMA_NODES + 1, 1) == 0) {
                for (size_t i = 0; i < buf_size; i += 4096)
                    ((volatile char*)buf)[i] = 0xAA;
                bufs[d] = (char*)buf;
            } else {
                munmap(buf, buf_size);
            }
        }
        
        for (int s = 0; s < num_online_nodes; s++) {
            if (node_to_cpu_map[s] == -1) continue;
            cpu_set_t mask;
            CPU_ZERO(&mask);
            CPU_SET(node_to_cpu_map[s], &mask);
            sched_setaffinity(0, sizeof(mask), &mask);
            
            for (int d = 0; d < num_online_nodes; d++) {
                if (!bufs[d]) { results[s][d] = 99999.0; continue; }
                
                char *buf = bufs[d];
                
                for (size_t i = 0; i < buf_size; i += 64)
                    clflush(buf + i);
                mfence();
                
                uint64_t total = 0;
                unsigned int seed = s * 1000 + d;
                
                for (int i = 0; i < PTL_ITERATIONS; i++) {
                    size_t offset = (rand_r(&seed) % (buf_size / 64)) * 64;
                    char *addr = buf + offset;
                    
                    clflush(addr);
                    mfence();
                    
                    uint64_t start = rdtsc_fenced();
                    
                    char val;
                    asm volatile(
                        "movb (%1), %0"
                        : "=r"(val)
                        : "r"(addr)
                        : "memory"
                    );
                    
                    uint64_t end = rdtsc_fenced();
                    total += (end - start);
                    
                    if (val == 0x7F) seed++;
                }
                
                results[s][d] = (double)total / PTL_ITERATIONS / cpu_ghz;
            }
        }
        
        for (int d = 0; d < num_online_nodes; d++)
            if (bufs[d]) munmap(bufs[d], buf_size);
        _exit(0);
    } else if (pid > 0) {
        waitpid(pid, NULL, 0);
        for (int s = 0; s < num_online_nodes; s++)
            for (int d = 0; d < num_online_nodes; d++)
                ptl_matrix[s][d] = results[s][d];
    }
    
    munmap(results, sizeof(double) * MAX_NUMA_NODES * MAX_NUMA_NODES);
    last_ptl_duration = get_time_ms() - start_time;
    ptl_measuring = 0;
    
    compute_steering_matrix();
}

// ============================================================================
// PERF COUNTERS
// ============================================================================

static int setup_counter(perf_counter_t *pc, pid_t pid, uint32_t type, uint64_t config) {
    memset(&pc->pe, 0, sizeof(pc->pe));
    pc->pe.type = type;
    pc->pe.size = sizeof(pc->pe);
    pc->pe.config = config;
    pc->pe.disabled = 1;
    pc->pe.exclude_kernel = 1;
    pc->pe.exclude_hv = 1;
    pc->pe.inherit = 0;
    pc->fd = perf_event_open(&pc->pe, pid, -1, -1, 0);
    if (pc->fd == -1) return 0;
    ioctl(pc->fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(pc->fd, PERF_EVENT_IOC_ENABLE, 0);
    return 1;
}

static long long read_counter(perf_counter_t *pc) {
    long long val = 0;
    if (pc->fd != -1) read(pc->fd, &val, sizeof(val));
    return val;
}

static void close_counter(perf_counter_t *pc) {
    if (pc->fd != -1) { close(pc->fd); pc->fd = -1; }
}

// ============================================================================
// PROCESS MANAGEMENT
// ============================================================================

static int is_kernel_thread(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    FILE *f = fopen(path, "r");
    if (f) { int c = fgetc(f); fclose(f); return (c == EOF); }
    return 1;
}

static void get_process_name(pid_t pid, char *name, size_t len) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    FILE *f = fopen(path, "r");
    if (f) {
        if (fgets(name, len, f)) {
            char *nl = strchr(name, '\n');
            if (nl) *nl = '\0';
        }
        fclose(f);
    } else {
        snprintf(name, len, "???");
    }
}

static int get_page_faults(pid_t pid, long long *majflt, long long *minflt) {
    char path[64], buf[1024];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    
    *majflt = 0; *minflt = 0;
    
    if (fgets(buf, sizeof(buf), f)) {
        char *p = strrchr(buf, ')');
        if (p) {
            long long minflt_val, cminflt, majflt_val, cmajflt;
            if (sscanf(p + 2, "%*c %*d %*d %*d %*d %*d %*u %lld %lld %lld %lld",
                       &minflt_val, &cminflt, &majflt_val, &cmajflt) == 4) {
                *minflt = minflt_val;
                *majflt = majflt_val;
                fclose(f);
                return 1;
            }
        }
    }
    fclose(f);
    return 0;
}

static process_t* find_process(pid_t tgid) {
    for (int i = 0; i < num_procs; i++)
        if (procs[i].active && procs[i].tgid == tgid) return &procs[i];
    return NULL;
}

static pid_t get_tgid(pid_t pid) {
    char path[64], buf[256];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    FILE *f = fopen(path, "r");
    if (!f) return pid;
    
    pid_t tgid = pid;
    while (fgets(buf, sizeof(buf), f)) {
        if (sscanf(buf, "Tgid: %d", &tgid) == 1) break;
    }
    fclose(f);
    return tgid;
}

static void add_process(pid_t pid) {
    pid_t tgid = get_tgid(pid);
    
    if (find_process(tgid) || tgid == daemon_pid || is_kernel_thread(tgid)) return;
    
    char name[32];
    get_process_name(tgid, name, sizeof(name));
    if (is_system_process(name)) return;
    
    process_t *p = NULL;
    for (int i = 0; i < num_procs; i++) {
        if (!procs[i].active) { p = &procs[i]; break; }
    }
    
    if (!p) {
        if (num_procs >= MAX_PROCS) return;
        p = &procs[num_procs];
        num_procs++;
    }
    
    memset(p, 0, sizeof(*p));
    p->tgid = tgid;
    p->mem_loads.fd = -1;
    p->dtlb_walks.fd = -1;
    p->dtlb_accesses.fd = -1;
    
    strncpy(p->name, name, sizeof(p->name) - 1);
    
    if (!setup_counter(&p->mem_loads, tgid, PERF_TYPE_HW_CACHE,
        PERF_COUNT_HW_CACHE_L1D | (PERF_COUNT_HW_CACHE_OP_READ << 8) |
        (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16))) {
        return;
    }
    setup_counter(&p->dtlb_accesses, tgid, PERF_TYPE_HW_CACHE,
        PERF_COUNT_HW_CACHE_DTLB | (PERF_COUNT_HW_CACHE_OP_READ << 8) |
        (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16));
    setup_counter(&p->dtlb_walks, tgid, PERF_TYPE_HW_CACHE,
        PERF_COUNT_HW_CACHE_DTLB | (PERF_COUNT_HW_CACHE_OP_READ << 8) |
        (PERF_COUNT_HW_CACHE_RESULT_MISS << 16));
    
    p->prev_mem_loads = read_counter(&p->mem_loads);
    p->prev_dtlb_accesses = (p->dtlb_accesses.fd != -1) ? read_counter(&p->dtlb_accesses) : 0;
    p->prev_dtlb_walks = (p->dtlb_walks.fd != -1) ? read_counter(&p->dtlb_walks) : 0;
    p->last_sample_time = get_time_ms();
    
    get_page_faults(tgid, &p->prev_majflt, &p->prev_minflt);
    p->last_pf_sample_time = p->last_sample_time;
    
    p->above_threshold_since = 0;
    p->below_threshold_since = 0;
    
    p->active = 1;
}

static void cleanup_dead_processes(void) {
    for (int i = 0; i < num_procs; i++) {
        if (!procs[i].active) continue;
        if (kill(procs[i].tgid, 0) == -1 && errno == ESRCH) {
            if (procs[i].mitosis_enabled) mitosis_count--;
            close_counter(&procs[i].mem_loads);
            close_counter(&procs[i].dtlb_accesses);
            close_counter(&procs[i].dtlb_walks);
            procs[i].active = 0;
        }
    }
}

static void scan_processes(void) {
    DIR *d = opendir("/proc");
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_type == DT_DIR || e->d_type == DT_UNKNOWN) {
            int is_num = 1;
            for (char *p = e->d_name; *p; p++)
                if (!isdigit(*p)) { is_num = 0; break; }
            if (is_num) add_process(atoi(e->d_name));
        }
    }
    closedir(d);
}

// ============================================================================
// MITOSIS CONTROL VIA PRCTL
// ============================================================================

static void apply_steering_matrix(process_t *p) {
    if (!p->mitosis_enabled) return;
    
    /*
     * PR_SET_PGTABLE_REPL_STEERING:
     *   arg2 = pointer to int[NUMA_NODE_COUNT] steering array
     *   arg3 = target PID (0 = self, >0 = other process)
     */
    if (prctl(PR_SET_PGTABLE_REPL_STEERING, steering_matrix, p->tgid, 0, 0) != 0) {
        /* Ignore errors - process may have exited */
    }
}

static void enable_mitosis(process_t *p) {
    if (p->mitosis_enabled) return;
    
    /*
     * PR_SET_PGTABLE_REPL:
     *   arg2 = 0: disable
     *   arg2 = 1: enable on all online nodes
     *   arg2 = bitmask: enable on specific nodes
     *   arg3 = target PID (0 = self, >0 = other process)
     */
    if (prctl(PR_SET_PGTABLE_REPL, 1, p->tgid, 0, 0) == 0) {
        p->mitosis_enabled = 1;
        mitosis_count++;
        apply_steering_matrix(p);
    }
}

static void disable_mitosis(process_t *p) {
    if (!p->mitosis_enabled) return;
    
    if (prctl(PR_SET_PGTABLE_REPL, 0, p->tgid, 0, 0) == 0) {
        p->mitosis_enabled = 0;
        mitosis_count--;
    }
}

// ============================================================================
// MAIN LOOP LOGIC
// ============================================================================

static void update_and_decide(void) {
    double now = get_time_ms();
    
    for (int i = 0; i < num_procs; i++) {
        process_t *p = &procs[i];
        if (!p->active) continue;
        
        long long ml = read_counter(&p->mem_loads);
        long long da = (p->dtlb_accesses.fd != -1) ? read_counter(&p->dtlb_accesses) : 0;
        long long dw = (p->dtlb_walks.fd != -1) ? read_counter(&p->dtlb_walks) : 0;
        
        long long d_mem = ml - p->prev_mem_loads;
        long long d_acc = da - p->prev_dtlb_accesses;
        long long d_walk = dw - p->prev_dtlb_walks;
        
        double elapsed_ms = now - p->last_sample_time;
        if (elapsed_ms < 1.0) elapsed_ms = 1.0;
        
        p->prev_mem_loads = ml;
        p->prev_dtlb_accesses = da;
        p->prev_dtlb_walks = dw;
        p->last_sample_time = now;
        
        if (d_mem < 0) d_mem = 0;
        if (d_acc < 0) d_acc = 0;
        if (d_walk < 0) d_walk = 0;
        
        p->last_mar = (double)d_mem * 1000.0 / elapsed_ms;
        p->last_dtlb_mr = (d_acc > 0) ? (double)d_walk / d_acc : 0.0;
        
        if (now - p->last_pf_sample_time >= PF_SAMPLE_INTERVAL) {
            long long majflt, minflt;
            if (get_page_faults(p->tgid, &majflt, &minflt)) {
                double pf_elapsed = now - p->last_pf_sample_time;
                long long d_faults = (minflt - p->prev_minflt) + (majflt - p->prev_majflt);
                if (d_faults < 0) d_faults = 0;
                p->last_pf_rate = (double)d_faults * 1000.0 / pf_elapsed;
                p->prev_majflt = majflt;
                p->prev_minflt = minflt;
                p->last_pf_sample_time = now;
            }
        }
        
        int above_threshold = (p->last_mar > THR_MAR) && (p->last_dtlb_mr > THR_DTLB);
        
        if (above_threshold) {
            p->below_threshold_since = 0;
            if (p->above_threshold_since == 0) {
                p->above_threshold_since = now;
            }
            
            if (!p->mitosis_enabled && (now - p->above_threshold_since) >= HYSTERESIS_MS) {
                enable_mitosis(p);
            }
        } else {
            p->above_threshold_since = 0;
            if (p->below_threshold_since == 0) {
                p->below_threshold_since = now;
            }
            
            if (p->mitosis_enabled && (now - p->below_threshold_since) >= HYSTERESIS_MS) {
                disable_mitosis(p);
            }
        }
    }
}

static void update_all_steering(void) {
    for (int i = 0; i < num_procs; i++) {
        if (procs[i].active && procs[i].mitosis_enabled) {
            apply_steering_matrix(&procs[i]);
        }
    }
}

// ============================================================================
// TUI DRAWING
// ============================================================================

static double get_process_priority(process_t *p) {
    if (p->mitosis_enabled) return 1e12;
    
    double mar_ratio = (THR_MAR > 0) ? p->last_mar / THR_MAR : 0;
    double dtlb_ratio = (THR_DTLB > 0) ? p->last_dtlb_mr / THR_DTLB : 0;
    double closeness = mar_ratio * dtlb_ratio;
    if (closeness > 0) closeness = sqrt(closeness);
    
    return closeness * 1e6;
}

static int compare_proc_priority(const void *a, const void *b) {
    int idx_a = *(const int *)a;
    int idx_b = *(const int *)b;
    
    double pri_a = get_process_priority(&procs[idx_a]);
    double pri_b = get_process_priority(&procs[idx_b]);
    
    if (pri_b > pri_a) return 1;
    if (pri_b < pri_a) return -1;
    return 0;
}

static void draw_header(void) {
    GOTO(1, 1);
    printf(BG_BLUE BOLD "  WASP - Workload-Aware Self-Replicating Page-Tables");
    for (int i = 52; i < term_cols; i++) printf(" ");
    printf(RESET);
    
    GOTO(2, 1);
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    printf(DIM " CPU: %.2f GHz | Nodes: %d | Hyst: %dms | %02d:%02d:%02d",
           cpu_ghz, num_online_nodes, HYSTERESIS_MS, tm->tm_hour, tm->tm_min, tm->tm_sec);
    printf(ESC "[K" RESET);
    
    /* Mitosis kernel status */
    GOTO(3, 1);
    if (mitosis_available) {
        const char *inh_str = (mitosis_inherit == 1) ? "on" : "off";
        printf(CYAN " Mitosis:" RESET " inherit=%s cache=%zuKB",
               inh_str, (cache_total_pages * 4));
    } else {
        printf(RED " Mitosis: kernel module not loaded" RESET);
    }
    printf(ESC "[K");
}

static void draw_ptl_matrix(int start_row) {
    GOTO(start_row, 1);
    printf(BOLD " PTL Latency Matrix (ns)" RESET);
    if (ptl_measuring) 
        printf(YELLOW " [measuring...]" RESET);
    else if (last_ptl_duration > 0)
        printf(DIM " [%.0fms]" RESET, last_ptl_duration);
    printf(ESC "[K");
    
    int row = start_row + 1;
    
    GOTO(row, 1);
    printf(DIM "      ");
    for (int d = 0; d < num_online_nodes; d++)
        if (node_to_cpu_map[d] != -1) printf(" %4d", d);
    printf(ESC "[K" RESET);
    row++;
    
    for (int s = 0; s < num_online_nodes; s++) {
        if (node_to_cpu_map[s] == -1) continue;
        
        GOTO(row, 1);
        printf(DIM "  %2d:" RESET, s);
        
        double min = 99999.0;
        for (int d = 0; d < num_online_nodes; d++)
            if (node_to_cpu_map[d] != -1 && ptl_matrix[s][d] > 0 && ptl_matrix[s][d] < min)
                min = ptl_matrix[s][d];
        
        for (int d = 0; d < num_online_nodes; d++) {
            if (node_to_cpu_map[d] == -1) continue;
            double lat = ptl_matrix[s][d];
            int is_steered = (steering_matrix[s] == d);
            if (lat == 0)
                printf(DIM "    -" RESET);
            else if (is_steered)
                printf(GREEN BOLD " %4.0f" RESET, lat);
            else if (lat < min * 1.5)
                printf(YELLOW " %4.0f" RESET, lat);
            else
                printf(RED " %4.0f" RESET, lat);
        }
        printf(ESC "[K");
        row++;
    }
    
    row++;
    GOTO(row, 1);
    printf(CYAN " Steering:" RESET " ");
    for (int s = 0; s < num_online_nodes; s++) {
        if (node_to_cpu_map[s] == -1) continue;
        int target = steering_matrix[s];
        if (target >= 0 && target != s) {
            printf("%d->%d ", s, target);
        }
    }
    printf(ESC "[K");
}

static void draw_processes(int start_row, int *end_row) {
    GOTO(start_row, 1);
    printf(BOLD " Mitosis: %d" RESET " | tracking %d" ESC "[K", mitosis_count, num_procs);
    
    int row = start_row + 1;
    GOTO(row, 1);
    printf(DIM "  %-7s %-10s %9s %6s %8s %8s" RESET ESC "[K",
           "PID", "Name", "MAR", "DTLB%", "Status", "Hyst");
    row++;
    
    int sorted_idx[MAX_PROCS];
    int active_count = 0;
    for (int i = 0; i < num_procs; i++) {
        if (procs[i].active)
            sorted_idx[active_count++] = i;
    }
    qsort(sorted_idx, active_count, sizeof(int), compare_proc_priority);
    
    int max_row = term_rows - 2;
    double now = get_time_ms();
    
    for (int j = 0; j < active_count && row < max_row; j++) {
        process_t *p = &procs[sorted_idx[j]];
        
        GOTO(row, 1);
        
        const char *status;
        const char *color;
        char hyst_buf[16] = "";
        
        if (p->mitosis_enabled) {
            status = "ACTIVE";
            color = GREEN;
            if (p->below_threshold_since > 0) {
                int remaining = HYSTERESIS_MS - (int)(now - p->below_threshold_since);
                if (remaining > 0)
                    snprintf(hyst_buf, sizeof(hyst_buf), "-%dms", remaining);
            }
        } else {
            status = "watch";
            color = DIM;
            if (p->above_threshold_since > 0) {
                int elapsed = (int)(now - p->above_threshold_since);
                int remaining = HYSTERESIS_MS - elapsed;
                if (remaining > 0)
                    snprintf(hyst_buf, sizeof(hyst_buf), "+%dms", elapsed);
            }
        }
        
        printf("  %s%-7d %-10.10s %9.2e %5.2f%% %8s %8s" RESET ESC "[K",
               color, p->tgid, p->name, p->last_mar, p->last_dtlb_mr * 100, status, hyst_buf);
        row++;
    }
    
    *end_row = row;
}

static void draw_footer(void) {
    GOTO(term_rows, 1);
    printf(BG_BLUE " q" RESET " Quit  ");
    printf(BG_BLUE " r" RESET " Remeasure  ");
    printf(BG_BLUE " c" RESET " Cache+100  ");
    printf(BG_BLUE " d" RESET " DrainCache  ");
    printf(BG_BLUE " m" RESET " ToggleMode");
    for (int i = 70; i < term_cols; i++) printf(" ");
}

static void draw_screen(void) {
    get_term_size();
    printf(HOME CLEAR);
    
    draw_header();
    
    int matrix_height = num_online_nodes + 3;
    draw_ptl_matrix(5);
    int end_row;
    draw_processes(5 + matrix_height + 1, &end_row);
    
    for (int r = end_row; r < term_rows - 1; r++) {
        GOTO(r, 1);
        printf(ESC "[K");
    }
    
    draw_footer();
    
    fflush(stdout);
}

// ============================================================================
// SIGNAL HANDLING
// ============================================================================

static void signal_handler(int sig) { 
    (void)sig; 
    stop_requested = 1; 
}

static void cleanup(void) {
    for (int i = 0; i < num_procs; i++) {
        if (!procs[i].active) continue;
        if (procs[i].mitosis_enabled)
            prctl(PR_SET_PGTABLE_REPL, 0, procs[i].tgid, 0, 0);
        close_counter(&procs[i].mem_loads);
        close_counter(&procs[i].dtlb_accesses);
        close_counter(&procs[i].dtlb_walks);
    }
}

// ============================================================================
// MAIN
// ============================================================================

static void print_usage(const char *prog) {
    printf("Usage: %s [options]\n", prog);
    printf("  -i N     PTL measurement interval in ms [default: %d]\n", PTL_UPDATE_INTERVAL);
    printf("  -u N     Main loop interval in ms [default: %d]\n", UPDATE_INTERVAL_MS);
    printf("  -y N     Hysteresis duration in ms [default: %d]\n", HYSTERESIS_MS);
    printf("  -c N     Pre-populate cache with N pages/node\n");
    printf("  -h       Show this help\n");
}

int main(int argc, char *argv[]) {
    int initial_cache = 0;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0) { print_usage(argv[0]); return 0; }
        else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) ptl_interval = atoi(argv[++i]);
        else if (strcmp(argv[i], "-u") == 0 && i + 1 < argc) UPDATE_INTERVAL_MS = atoi(argv[++i]);
        else if (strcmp(argv[i], "-y") == 0 && i + 1 < argc) HYSTERESIS_MS = atoi(argv[++i]);
        else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) initial_cache = atoi(argv[++i]);
    }
    
    daemon_pid = getpid();
    detect_cpu_freq();
    
    struct rlimit rlim = {65536, 65536};
    setrlimit(RLIMIT_NOFILE, &rlim);
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    init_topology();
    
    if (num_online_nodes < 2) {
        fprintf(stderr, "Error: need >= 2 NUMA nodes\n");
        return 1;
    }
    
    /* Check mitosis availability and optionally populate cache */
    mitosis_available = mitosis_check_available();
    if (mitosis_available) {
        mitosis_update_status();
        
	/* Disable inheritance - WASP manages replication per-process */
        mitosis_set_inherit(0);
	
	if (initial_cache > 0) {
            mitosis_populate_cache(initial_cache);
        }
    }
    
    term_init();
    
    last_ptl_update = 0;
    
    while (!stop_requested) {
        char c;
        if (read(STDIN_FILENO, &c, 1) == 1) {
            if (c == 'q' || c == 'Q') break;
            if (c == 'r' || c == 'R') {
                last_ptl_update = 0;
            }
            if (c == 'c' || c == 'C') {
                /* Add 100 pages per node to cache */
                if (mitosis_available) {
                    mitosis_populate_cache(100);
                }
            }
            if (c == 'd' || c == 'D') {
                /* Drain cache */
                if (mitosis_available) {
                    mitosis_drain_cache();
                }
            }
            if (c == 'm' || c == 'M') {
                /* Toggle mode: -1 -> 0 -> 1 -> -1 */
                if (mitosis_available) {
                    int new_mode = (mitosis_mode + 2) % 3 - 1;
                    mitosis_set_mode(new_mode);
                }
            }
        }
        
        cleanup_dead_processes();
        scan_processes();
        
        double old_ptl_update = last_ptl_update;
        update_ptl_matrix();
        
        if (last_ptl_update != old_ptl_update) {
            update_all_steering();
        }
        
        update_and_decide();
        mitosis_update_status();
        draw_screen();
        
        usleep(UPDATE_INTERVAL_MS * 1000);
    }
    
    term_restore();
    cleanup();
    
    printf("WASP terminated.\n");
    return 0;
}
