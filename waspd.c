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

#define MAX_NUMA_NODES  64
#define MAX_PROCS       256
#define MAX_THREADS     256

#define PTL_ITERATIONS      1000
#define PTL_WARMUP           100
#define PTL_UPDATE_INTERVAL 1000
#define PTL_PAGES           64

static double THR_MAR  = 10.0 * 1000000.0;
static double THR_DTLB = 0.01;
#define PF_SAMPLE_INTERVAL  1000

static int UPDATE_INTERVAL_MS = 1000;
static int HYSTERESIS_MS = 1000;

static int numa_node_count = 0;

static int node_mask_enabled[MAX_NUMA_NODES];
static int node_mask_set = 0;
static int active_node_count = 0;

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

#define MITOSIS_PROC_DIR     "/proc/mitosis"
#define MITOSIS_MODE_PATH    MITOSIS_PROC_DIR "/mode"
#define MITOSIS_INHERIT_PATH MITOSIS_PROC_DIR "/inherit"
#define MITOSIS_CACHE_PATH   MITOSIS_PROC_DIR "/cache"

#define SNB_DTLB_LOAD_MISS_WALK       0x0108
#define SNB_DTLB_LOAD_WALK_COMPLETED  0x0208
#define SNB_DTLB_LOAD_WALK_DURATION   0x0408
#define SNB_DTLB_LOAD_STLB_HIT        0x1008

#define SNB_MEM_LOAD_RETIRED_L1_HIT   0x01D1
#define SNB_MEM_LOAD_RETIRED_L2_HIT   0x02D1
#define SNB_MEM_LOAD_RETIRED_L3_HIT   0x04D1
#define SNB_MEM_LOAD_RETIRED_L1_MISS  0x08D1

#define SNB_MEM_UOPS_RETIRED_ALL_LOADS  0x81D0
#define SNB_MEM_UOPS_RETIRED_ALL_STORES 0x82D0

#define SKX_DTLB_LOAD_MISS_WALK       0x0108
#define SKX_DTLB_LOAD_WALK_COMPLETED  0x0E08
#define SKX_DTLB_LOAD_WALK_PENDING    0x1008
#define SKX_DTLB_LOAD_STLB_HIT        0x2008

#define SKX_MEM_LOAD_RETIRED_L1_HIT   0x01D1
#define SKX_MEM_LOAD_RETIRED_L2_HIT   0x02D1
#define SKX_MEM_LOAD_RETIRED_L3_HIT   0x04D1
#define SKX_MEM_LOAD_RETIRED_L1_MISS  0x08D1

#define SKX_MEM_INST_RETIRED_ALL_LOADS  0x81D0
#define SKX_MEM_INST_RETIRED_ALL_STORES 0x82D0

#define ICX_DTLB_LOAD_MISS_WALK       0x0108
#define ICX_DTLB_LOAD_WALK_COMPLETED  0x0E08
#define ICX_DTLB_LOAD_WALK_PENDING    0x1008

#define ICX_MEM_LOAD_RETIRED_L1_HIT   0x01D1
#define ICX_MEM_INST_RETIRED_ALL_LOADS 0x81D0

#define AMD_DTLB_LOAD_MISS_WALK       0xFF45
#define AMD_L1_DTLB_MISS              0xF045
#define AMD_LS_DISPATCH_LOADS          0x0029
#define AMD_LS_DISPATCH_ALL            0x0729

enum intel_uarch {
    UARCH_UNKNOWN = 0,
    UARCH_SNB,
    UARCH_HSW,
    UARCH_SKX,
    UARCH_ICX,
};

static const char *SYSTEM_BLACKLIST[] = {
    "bash","sh","zsh","fish","csh","tcsh","ksh","dash",
    "ssh","sshd","sftp","scp",
    "login","getty","agetty",
    "systemd","init","launchd",
    "cron","crond","atd",
    "dbus","dbus-daemon","dbus-broker",
    "udev","udevd","systemd-udevd",
    "journald","systemd-journald","rsyslogd","syslogd",
    "NetworkManager","dhclient","dhcpcd","wpa_supplicant",
    "polkitd","accounts-daemon",
    "sudo","su","pkexec",
    "tmux","screen","tmux:server",
    "vim","nvim","nano","emacs","vi",
    "less","more","cat","grep","awk","sed",
    "top","htop","ps","watch",
    "ls","find","xargs","head","tail",
    "waspd","wasp","perf", "pwc_polluter",
    NULL
};

static int is_system_process(const char *name) {
    for (int i = 0; SYSTEM_BLACKLIST[i]; i++)
        if (strcmp(name, SYSTEM_BLACKLIST[i]) == 0) return 1;
    if (strncmp(name, "systemd-", 8) == 0) return 1;
    if (strncmp(name, "kworker", 7) == 0) return 1;
    if (strncmp(name, "ksoftirq", 8) == 0) return 1;
    if (strncmp(name, "migration", 9) == 0) return 1;
    if (strncmp(name, "rcu_", 4) == 0) return 1;
    return 0;
}

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

volatile sig_atomic_t stop_requested = 0;
static pid_t daemon_pid = 0;
static double cpu_ghz = 2.2;
static int ptl_interval = PTL_UPDATE_INTERVAL;
static struct termios orig_termios;
static int term_rows = 24, term_cols = 80;

static int cpu_vendor = 0;
static int cpu_model  = -1;
static int cpu_family = -1;
static enum intel_uarch intel_arch = UARCH_UNKNOWN;
static char uarch_name[32] = "unknown";

int node_to_cpu_map[MAX_NUMA_NODES];
double ptl_matrix[MAX_NUMA_NODES][MAX_NUMA_NODES];
int steering_matrix[MAX_NUMA_NODES];
double last_ptl_update = 0, last_ptl_duration = 0;
int ptl_measuring = 0;

static int use_raw_events = 1, raw_events_tested = 0;

int mitosis_available = 0, mitosis_mode = -1, mitosis_inherit = 1;
size_t cache_total_pages = 0;
size_t cache_per_node[MAX_NUMA_NODES];

static size_t   ptl_buf_size = 0;
static char    *ptl_bufs[MAX_NUMA_NODES];
static double (*ptl_shared_results)[MAX_NUMA_NODES];
static int      ptl_buffers_ready = 0;

typedef struct {
    long long value;
    uint64_t  time_enabled;
    uint64_t  time_running;
} counter_reading_t;

typedef struct {
    int fds[MAX_THREADS];
    int num_fds;
    struct perf_event_attr pe;
    int is_raw;
} perf_counter_t;

typedef struct {
    pid_t tgid;
    char name[32];
    perf_counter_t mem_loads;
    perf_counter_t dtlb_walks;
    perf_counter_t dtlb_walk_completed;
    counter_reading_t prev_mem_loads_rd;
    counter_reading_t prev_dtlb_walks_rd;
    counter_reading_t prev_dtlb_walk_completed_rd;
    double last_sample_time;
    double last_mar;
    double last_dtlb_mr;
    double multiplex_pct;
    int mitosis_enabled;
    long long prev_majflt, prev_minflt;
    double last_pf_sample_time, last_pf_rate;
    int active;
    double above_threshold_since, below_threshold_since;
} process_t;

process_t procs[MAX_PROCS];
int num_procs = 0, mitosis_count = 0;

static inline int is_node_active(int n) {
    return (n >= 0 && n < MAX_NUMA_NODES && node_to_cpu_map[n] != -1);
}

static int count_active_nodes(void) {
    int c = 0;
    for (int i = 0; i < MAX_NUMA_NODES; i++)
        if (node_to_cpu_map[i] != -1) c++;
    return c;
}

static inline uint64_t rdtsc_fenced(void) {
    if (cpu_vendor == 2 || (cpu_vendor == 1 && intel_arch >= UARCH_SKX)) {
        uint32_t lo, hi, aux;
        asm volatile("rdtscp" : "=a"(lo), "=d"(hi), "=c"(aux));
        return ((uint64_t)hi << 32) | lo;
    } else {
        uint32_t lo, hi;
        asm volatile("lfence; rdtsc; lfence" : "=a"(lo), "=d"(hi));
        return ((uint64_t)hi << 32) | lo;
    }
}

static inline void clflush(void *p) { asm volatile("clflush (%0)" :: "r"(p) : "memory"); }
static inline void mfence(void) { asm volatile("mfence" ::: "memory"); }

static long perf_event_open(struct perf_event_attr *a, pid_t p,
                            int cpu, int gfd, unsigned long fl) {
    return syscall(__NR_perf_event_open, a, p, cpu, gfd, fl);
}
static long sys_mbind(void *s, unsigned long l, int m,
                      const unsigned long *nm, unsigned long mn, unsigned f) {
    return syscall(__NR_mbind, s, l, m, nm, mn, f);
}

static int detect_cpu_vendor(void) {
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (!f) return 0;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "vendor_id", 9) == 0) {
            if (strstr(line, "GenuineIntel")) { fclose(f); return 1; }
            if (strstr(line, "AuthenticAMD"))  { fclose(f); return 2; }
            fclose(f); return 0;
        }
    }
    fclose(f);
    return 0;
}

static int detect_cpu_model(void) {
    FILE *f = fopen("/proc/cpuinfo", "r"); if (!f) return -1;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        int m; if (sscanf(line, "model : %d", &m) == 1) { fclose(f); return m; }
    }
    fclose(f); return -1;
}

static int detect_cpu_family(void) {
    FILE *f = fopen("/proc/cpuinfo", "r"); if (!f) return -1;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        int fam; if (sscanf(line, "cpu family : %d", &fam) == 1) { fclose(f); return fam; }
    }
    fclose(f); return -1;
}

static enum intel_uarch classify_intel(int family, int model) {
    if (family != 6) return UARCH_UNKNOWN;
    switch (model) {
        case 42: case 45:
            snprintf(uarch_name, sizeof(uarch_name), "Sandy Bridge");
            return UARCH_SNB;
        case 58: case 62:
            snprintf(uarch_name, sizeof(uarch_name), "Ivy Bridge");
            return UARCH_SNB;
        case 60: case 63: case 69: case 70:
            snprintf(uarch_name, sizeof(uarch_name), "Haswell");
            return UARCH_HSW;
        case 61: case 71: case 79: case 86:
            snprintf(uarch_name, sizeof(uarch_name), "Broadwell");
            return UARCH_HSW;
        case 78: case 94:
            snprintf(uarch_name, sizeof(uarch_name), "Skylake");
            return UARCH_SKX;
        case 85:
            snprintf(uarch_name, sizeof(uarch_name), "Skylake-SP");
            return UARCH_SKX;
        case 106: case 108:
            snprintf(uarch_name, sizeof(uarch_name), "Ice Lake-SP");
            return UARCH_ICX;
        case 143:
            snprintf(uarch_name, sizeof(uarch_name), "Sapphire Rapids");
            return UARCH_ICX;
        case 207:
            snprintf(uarch_name, sizeof(uarch_name), "Emerald Rapids");
            return UARCH_ICX;
        default:
            snprintf(uarch_name, sizeof(uarch_name), "Intel model %d", model);
            if (model > 85) return UARCH_ICX;
            return UARCH_UNKNOWN;
    }
}

static void classify_cpu(void) {
    if (cpu_vendor == 1) {
        intel_arch = classify_intel(cpu_family, cpu_model);
    } else if (cpu_vendor == 2) {
        if (cpu_family == 23)
            snprintf(uarch_name, sizeof(uarch_name), "Zen/Zen2 (F17h)");
        else if (cpu_family == 25)
            snprintf(uarch_name, sizeof(uarch_name), "Zen3/Zen4 (F19h)");
        else
            snprintf(uarch_name, sizeof(uarch_name), "AMD F%dh", cpu_family);
    }
}

static double calibrate_tsc(void) {
    struct timespec ts_start, ts_end;
    uint64_t tsc_start, tsc_end;
    clock_gettime(CLOCK_MONOTONIC, &ts_start);
    tsc_start = rdtsc_fenced();
    usleep(50000);
    tsc_end = rdtsc_fenced();
    clock_gettime(CLOCK_MONOTONIC, &ts_end);
    double elapsed_ns = (ts_end.tv_sec - ts_start.tv_sec) * 1e9
                      + (ts_end.tv_nsec - ts_start.tv_nsec);
    if (elapsed_ns < 1e6) return 0.0;
    return (double)(tsc_end - tsc_start) / elapsed_ns;
}

static void detect_cpu_freq(void) {
    FILE *f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/base_frequency", "r");
    if (f) {
        double khz;
        if (fscanf(f, "%lf", &khz) == 1 && khz > 100000) {
            cpu_ghz = khz / 1e6;
            fclose(f);
            return;
        }
        fclose(f);
    }

    f = fopen("/proc/cpuinfo", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "model name", 10) == 0) {
                char *at = strstr(line, "@ ");
                if (at) {
                    double g;
                    if (sscanf(at, "@ %lfGHz", &g) == 1) {
                        cpu_ghz = g;
                        fclose(f);
                        return;
                    }
                }
            }
        }
        fclose(f);
    }

    f = fopen("/proc/cpuinfo", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            double bogo;
            if (sscanf(line, "bogomips : %lf", &bogo) == 1 ||
                sscanf(line, "BogoMIPS : %lf", &bogo) == 1) {
                if (bogo > 100.0) {
                    cpu_ghz = bogo / 2000.0;
                    fclose(f);
                    return;
                }
            }
        }
        fclose(f);
    }

    double cal = calibrate_tsc();
    if (cal > 0.5 && cal < 10.0) {
        cpu_ghz = cal;
        return;
    }

    cpu_ghz = 2.2;
}

static double get_time_ms(void) {
    struct timeval tv; gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
}

static counter_reading_t read_counter_full(perf_counter_t *pc) {
    counter_reading_t r = {0, 0, 0};
    struct { uint64_t val, ena, run; } buf;
    for (int i = 0; i < pc->num_fds; i++) {
        if (pc->fds[i] == -1) continue;
        ssize_t n = read(pc->fds[i], &buf, sizeof(buf));
        if (n == (ssize_t)sizeof(buf)) {
            r.value        += (long long)buf.val;
            r.time_enabled += buf.ena;
            r.time_running += buf.run;
        } else if (n == (ssize_t)sizeof(uint64_t)) {
            r.value += (long long)buf.val;
        }
    }
    return r;
}

static long long scaled_delta(const counter_reading_t *now,
                              const counter_reading_t *prev) {
    long long dv = now->value - prev->value;
    if (dv <= 0) return 0;
    uint64_t de = now->time_enabled - prev->time_enabled;
    uint64_t dr = now->time_running - prev->time_running;
    if (dr == 0) return 0;
    if (dr >= de) return dv;
    return (long long)((double)dv * (double)de / (double)dr);
}

static double mux_ratio(const counter_reading_t *now,
                        const counter_reading_t *prev) {
    uint64_t de = now->time_enabled - prev->time_enabled;
    uint64_t dr = now->time_running - prev->time_running;
    if (de == 0) return 1.0;
    double r = (double)dr / (double)de;
    return (r > 1.0) ? 1.0 : r;
}

static int mitosis_check_available(void) { return access(MITOSIS_PROC_DIR, F_OK) == 0; }

static int mitosis_read_int(const char *path) {
    FILE *f = fopen(path, "r"); if (!f) return -999;
    int v = -999;
    char buf[256];
    while (fgets(buf, sizeof(buf), f)) {
        if (sscanf(buf, "%d", &v) == 1) break;
        if (sscanf(buf, " Current mode: %d", &v) == 1) break;
    }
    fclose(f);
    return v;
}
static int mitosis_write_int(const char *path, int val) {
    FILE *f = fopen(path, "w"); if (!f) return -1;
    fprintf(f, "%d\n", val); fclose(f); return 0;
}

static void mitosis_read_cache_status(void) {
    cache_total_pages = 0; memset(cache_per_node, 0, sizeof(cache_per_node));
    FILE *f = fopen(MITOSIS_CACHE_PATH, "r"); if (!f) return;
    char line[256]; int node; int count;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%d %d", &node, &count) >= 2 && node >= 0 && node < MAX_NUMA_NODES)
            { cache_per_node[node] = count; cache_total_pages += count; }
    }
    fclose(f);
}

static void mitosis_update_status(void) {
    if (!mitosis_available) mitosis_available = mitosis_check_available();
    if (mitosis_available) {
        mitosis_mode = mitosis_read_int(MITOSIS_MODE_PATH);
        mitosis_inherit = mitosis_read_int(MITOSIS_INHERIT_PATH);
        mitosis_read_cache_status();
    }
}

static int mitosis_set_mode(int m)       { return mitosis_write_int(MITOSIS_MODE_PATH, m); }
static int mitosis_set_inherit(int i)    { return mitosis_write_int(MITOSIS_INHERIT_PATH, i); }
static int mitosis_populate_cache(int n) { return mitosis_write_int(MITOSIS_CACHE_PATH, n); }
static int mitosis_drain_cache(void)     { return mitosis_write_int(MITOSIS_CACHE_PATH, -1); }

static void get_term_size(void) {
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) { term_rows = ws.ws_row; term_cols = ws.ws_col; }
}
static void term_init(void) {
    tcgetattr(STDIN_FILENO, &orig_termios);
    struct termios raw = orig_termios;
    raw.c_lflag &= ~(ECHO | ICANON); raw.c_cc[VMIN] = 0; raw.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
    printf(ALT_BUF_ON HIDE_CUR CLEAR HOME); fflush(stdout);
}
static void term_restore(void) {
    printf(RESET SHOW_CUR ALT_BUF_OFF);
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios); fflush(stdout);
}

static int get_node_for_cpu(int cpu) {
    char p[128];
    for (int n = 0; n < MAX_NUMA_NODES; n++) {
        snprintf(p, sizeof(p), "/sys/devices/system/cpu/cpu%d/node%d", cpu, n);
        if (access(p, F_OK) == 0) return n;
    }
    return 0;
}

static int detect_numa_node_count(void) {
    int count = 0;
    for (int i = 0; i < MAX_NUMA_NODES; i++) {
        char p[64];
        snprintf(p, sizeof(p), "/sys/devices/system/node/node%d", i);
        if (access(p, F_OK) == 0) {
            if (i + 1 > count) count = i + 1;
        }
    }
    return count;
}

static void init_topology(void) {
    for (int i = 0; i < MAX_NUMA_NODES; i++) {
        node_to_cpu_map[i] = -1;
        steering_matrix[i] = -1;
        for (int j = 0; j < MAX_NUMA_NODES; j++) ptl_matrix[i][j] = 0;
    }

    numa_node_count = detect_numa_node_count();
    if (numa_node_count < 1) numa_node_count = 1;
    if (numa_node_count > MAX_NUMA_NODES) numa_node_count = MAX_NUMA_NODES;

    for (int cpu = 0; cpu < 4096; cpu++) {
        char p[128]; snprintf(p, sizeof(p), "/sys/devices/system/cpu/cpu%d", cpu);
        if (access(p, F_OK) != 0) break;
        int node = get_node_for_cpu(cpu);
        if (node < numa_node_count && node_to_cpu_map[node] == -1)
            node_to_cpu_map[node] = cpu;
    }
}

static void apply_node_subset(void) {
    if (!node_mask_set) return;
    for (int i = 0; i < MAX_NUMA_NODES; i++)
        if (!node_mask_enabled[i]) node_to_cpu_map[i] = -1;
    active_node_count = count_active_nodes();
}

static void compute_steering_matrix(void) {
    for (int ph = 0; ph < numa_node_count; ph++) {
        if (node_to_cpu_map[ph] == -1) { steering_matrix[ph] = -1; continue; }
        double best = 1e18; int bn = ph;
        for (int r = 0; r < numa_node_count; r++) {
            if (node_to_cpu_map[r] == -1) continue;
            double lat = ptl_matrix[ph][r];
            if (lat <= 0) continue;
            if (lat < best) { best = lat; bn = r; }
        }
        steering_matrix[ph] = bn;
    }
    for (int i = numa_node_count; i < MAX_NUMA_NODES; i++)
        steering_matrix[i] = -1;
}

static unsigned long build_node_bitmask(void) {
    unsigned long mask = 0;
    int count = 0;
    for (int i = 0; i < numa_node_count && i < (int)(sizeof(unsigned long) * 8); i++) {
        if (node_to_cpu_map[i] != -1) {
            mask |= (1UL << i);
            count++;
        }
    }
    return (count < 2) ? 0 : mask;
}

static void init_ptl_buffers(void) {
    ptl_buf_size = PTL_PAGES * 4096;

    ptl_shared_results = mmap(NULL,
        sizeof(double) * MAX_NUMA_NODES * MAX_NUMA_NODES,
        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (ptl_shared_results == MAP_FAILED) {
        ptl_shared_results = NULL;
        return;
    }

    for (int d = 0; d < MAX_NUMA_NODES; d++) {
        ptl_bufs[d] = NULL;
        if (node_to_cpu_map[d] == -1) continue;

        void *b = mmap(NULL, ptl_buf_size, PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (b == MAP_FAILED) continue;

        unsigned long nm = 1UL << d;
        if (sys_mbind(b, ptl_buf_size, 2, &nm, numa_node_count + 1, 1) == 0) {
            for (size_t i = 0; i < ptl_buf_size; i += 4096)
                ((volatile char *)b)[i] = 0xAA;
            ptl_bufs[d] = (char *)b;
        } else {
            munmap(b, ptl_buf_size);
        }
    }

    ptl_buffers_ready = 1;
}

static void cleanup_ptl_buffers(void) {
    for (int d = 0; d < MAX_NUMA_NODES; d++) {
        if (ptl_bufs[d]) {
            munmap(ptl_bufs[d], ptl_buf_size);
            ptl_bufs[d] = NULL;
        }
    }
    if (ptl_shared_results) {
        munmap(ptl_shared_results,
               sizeof(double) * MAX_NUMA_NODES * MAX_NUMA_NODES);
        ptl_shared_results = NULL;
    }
    ptl_buffers_ready = 0;
}

static void update_ptl_matrix(void) {
    double now = get_time_ms();
    if (now - last_ptl_update < ptl_interval) return;
    if (!ptl_buffers_ready || !ptl_shared_results) return;

    last_ptl_update = now;
    ptl_measuring = 1;
    double st = get_time_ms();

    memset(ptl_shared_results, 0,
           sizeof(double) * MAX_NUMA_NODES * MAX_NUMA_NODES);

    pid_t pid = fork();
    if (pid == 0) {
        for (int s = 0; s < numa_node_count; s++) {
            if (node_to_cpu_map[s] == -1) continue;
            cpu_set_t mask; CPU_ZERO(&mask);
            CPU_SET(node_to_cpu_map[s], &mask);
            sched_setaffinity(0, sizeof(mask), &mask);

            for (int d = 0; d < numa_node_count; d++) {
                if (node_to_cpu_map[d] == -1) {
                    ptl_shared_results[s][d] = 0;
                    continue;
                }
                if (!ptl_bufs[d]) {
                    ptl_shared_results[s][d] = 99999.0;
                    continue;
                }
                char *buf = ptl_bufs[d];

                for (size_t i = 0; i < ptl_buf_size; i += 64)
                    clflush(buf + i);
                mfence();

                unsigned int seed = s * 1000 + d;

                for (int i = 0; i < PTL_WARMUP; i++) {
                    size_t off = (rand_r(&seed) % (ptl_buf_size / 64)) * 64;
                    char *addr = buf + off;
                    clflush(addr); mfence();
                    char val;
                    asm volatile("movb (%1), %0"
                                 : "=r"(val) : "r"(addr) : "memory");
                    if (val == 0x7F) seed++;
                }

                uint64_t total = 0;
                for (int i = 0; i < PTL_ITERATIONS; i++) {
                    size_t off = (rand_r(&seed) % (ptl_buf_size / 64)) * 64;
                    char *addr = buf + off;
                    clflush(addr); mfence();
                    uint64_t t0 = rdtsc_fenced();
                    char val;
                    asm volatile("movb (%1), %0"
                                 : "=r"(val) : "r"(addr) : "memory");
                    uint64_t t1 = rdtsc_fenced();
                    total += (t1 - t0);
                    if (val == 0x7F) seed++;
                }
                ptl_shared_results[s][d] =
                    (double)total / PTL_ITERATIONS / cpu_ghz;
            }
        }
        _exit(0);
    } else if (pid > 0) {
        waitpid(pid, NULL, 0);
        for (int s = 0; s < numa_node_count; s++)
            for (int d = 0; d < numa_node_count; d++)
                ptl_matrix[s][d] = ptl_shared_results[s][d];
    }

    last_ptl_duration = get_time_ms() - st;
    ptl_measuring = 0;
    compute_steering_matrix();
}

static int get_thread_ids(pid_t tgid, pid_t *tids, int max) {
    char p[64]; snprintf(p, sizeof(p), "/proc/%d/task", tgid);
    DIR *d = opendir(p); if (!d) return 0;
    int c = 0; struct dirent *e;
    while ((e = readdir(d)) && c < max)
        if (e->d_name[0] >= '0' && e->d_name[0] <= '9') tids[c++] = atoi(e->d_name);
    closedir(d); return c;
}

static void close_counter(perf_counter_t *pc) {
    for (int i = 0; i < pc->num_fds; i++)
        if (pc->fds[i] != -1) { close(pc->fds[i]); pc->fds[i] = -1; }
    pc->num_fds = 0;
}

static void init_counter(perf_counter_t *pc) {
    memset(pc, 0, sizeof(*pc));
    for (int i = 0; i < MAX_THREADS; i++) pc->fds[i] = -1;
    pc->num_fds = 0;
}

static void init_pe_common(struct perf_event_attr *pe) {
    memset(pe, 0, sizeof(*pe));
    pe->size           = sizeof(*pe);
    pe->disabled       = 1;
    pe->exclude_kernel = 1;
    pe->exclude_hv     = 1;
    pe->inherit        = 0;
    pe->read_format    = PERF_FORMAT_TOTAL_TIME_ENABLED
                       | PERF_FORMAT_TOTAL_TIME_RUNNING;
}

static int open_counter_fds(perf_counter_t *pc, pid_t tgid) {
    pid_t tids[MAX_THREADS];
    int nt = get_thread_ids(tgid, tids, MAX_THREADS);
    if (nt == 0) return 0;
    int ok = 0;
    for (int i = 0; i < nt && pc->num_fds < MAX_THREADS; i++) {
        int fd = perf_event_open(&pc->pe, tids[i], -1, -1, 0);
        if (fd != -1) {
            ioctl(fd, PERF_EVENT_IOC_RESET, 0);
            ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
            pc->fds[pc->num_fds++] = fd;
            ok = 1;
        }
    }
    return ok;
}

static int setup_raw_counter(perf_counter_t *pc, pid_t tgid, uint64_t cfg) {
    init_counter(pc);
    init_pe_common(&pc->pe);
    pc->pe.type = PERF_TYPE_RAW; pc->pe.config = cfg; pc->is_raw = 1;
    return open_counter_fds(pc, tgid);
}

static int setup_cache_counter(perf_counter_t *pc, pid_t tgid,
                               uint64_t cid, uint64_t op, uint64_t res) {
    init_counter(pc);
    init_pe_common(&pc->pe);
    pc->pe.type = PERF_TYPE_HW_CACHE;
    pc->pe.config = cid | (op << 8) | (res << 16); pc->is_raw = 0;
    return open_counter_fds(pc, tgid);
}

static void test_raw_events(void) {
    if (raw_events_tested) return;
    raw_events_tested = 1;

    struct perf_event_attr pe;
    init_pe_common(&pe);
    pe.type = PERF_TYPE_RAW;

    if (cpu_vendor == 2) {
        pe.config = AMD_L1_DTLB_MISS;
    } else if (cpu_vendor == 1 && intel_arch >= UARCH_SKX) {
        pe.config = SKX_DTLB_LOAD_MISS_WALK;
    } else if (cpu_vendor == 1) {
        pe.config = SNB_DTLB_LOAD_MISS_WALK;
    } else {
        use_raw_events = 0;
        return;
    }

    int fd = perf_event_open(&pe, 0, -1, -1, 0);
    if (fd != -1) { close(fd); use_raw_events = 1; }
    else use_raw_events = 0;
}

static int setup_process_counters_intel_skx(process_t *p) {
    if (!setup_raw_counter(&p->mem_loads, p->tgid, SKX_MEM_LOAD_RETIRED_L1_HIT))
        if (!setup_raw_counter(&p->mem_loads, p->tgid, SKX_MEM_INST_RETIRED_ALL_LOADS))
            setup_cache_counter(&p->mem_loads, p->tgid,
                PERF_COUNT_HW_CACHE_L1D, PERF_COUNT_HW_CACHE_OP_READ, PERF_COUNT_HW_CACHE_RESULT_ACCESS);

    if (!setup_raw_counter(&p->dtlb_walks, p->tgid, SKX_DTLB_LOAD_MISS_WALK))
        setup_raw_counter(&p->dtlb_walks, p->tgid, SKX_DTLB_LOAD_WALK_COMPLETED);

    setup_raw_counter(&p->dtlb_walk_completed, p->tgid, SKX_DTLB_LOAD_WALK_COMPLETED);
    return (p->mem_loads.num_fds > 0);
}

static int setup_process_counters_intel_snb(process_t *p) {
    if (!setup_raw_counter(&p->mem_loads, p->tgid, SNB_MEM_LOAD_RETIRED_L1_HIT))
        if (!setup_raw_counter(&p->mem_loads, p->tgid, SNB_MEM_UOPS_RETIRED_ALL_LOADS))
            setup_cache_counter(&p->mem_loads, p->tgid,
                PERF_COUNT_HW_CACHE_L1D, PERF_COUNT_HW_CACHE_OP_READ, PERF_COUNT_HW_CACHE_RESULT_ACCESS);

    if (!setup_raw_counter(&p->dtlb_walks, p->tgid, SNB_DTLB_LOAD_MISS_WALK))
        setup_raw_counter(&p->dtlb_walks, p->tgid, SNB_DTLB_LOAD_WALK_COMPLETED);

    setup_raw_counter(&p->dtlb_walk_completed, p->tgid, SNB_DTLB_LOAD_WALK_COMPLETED);
    return (p->mem_loads.num_fds > 0);
}

static int setup_process_counters_amd(process_t *p) {
    if (!setup_raw_counter(&p->mem_loads, p->tgid, AMD_LS_DISPATCH_LOADS))
        if (!setup_raw_counter(&p->mem_loads, p->tgid, AMD_LS_DISPATCH_ALL))
            setup_cache_counter(&p->mem_loads, p->tgid,
                PERF_COUNT_HW_CACHE_L1D, PERF_COUNT_HW_CACHE_OP_READ, PERF_COUNT_HW_CACHE_RESULT_ACCESS);

    if (!setup_raw_counter(&p->dtlb_walks, p->tgid, AMD_L1_DTLB_MISS))
        setup_raw_counter(&p->dtlb_walks, p->tgid, AMD_DTLB_LOAD_MISS_WALK);

    init_counter(&p->dtlb_walk_completed);
    return (p->mem_loads.num_fds > 0);
}

static int setup_process_counters_generic(process_t *p) {
    setup_cache_counter(&p->mem_loads, p->tgid,
        PERF_COUNT_HW_CACHE_L1D, PERF_COUNT_HW_CACHE_OP_READ, PERF_COUNT_HW_CACHE_RESULT_ACCESS);
    setup_cache_counter(&p->dtlb_walks, p->tgid,
        PERF_COUNT_HW_CACHE_DTLB, PERF_COUNT_HW_CACHE_OP_READ, PERF_COUNT_HW_CACHE_RESULT_MISS);
    init_counter(&p->dtlb_walk_completed);
    return (p->mem_loads.num_fds > 0);
}

static int setup_process_counters(process_t *p) {
    test_raw_events();

    if (use_raw_events) {
        if (cpu_vendor == 2)
            return setup_process_counters_amd(p);
        if (cpu_vendor == 1 && intel_arch >= UARCH_SKX)
            return setup_process_counters_intel_skx(p);
        if (cpu_vendor == 1)
            return setup_process_counters_intel_snb(p);
    }
    return setup_process_counters_generic(p);
}

static void refresh_process_counters(process_t *p) {
    pid_t tids[MAX_THREADS];
    int nt = get_thread_ids(p->tgid, tids, MAX_THREADS);
    if (nt <= p->mem_loads.num_fds) return;

    for (int i = p->mem_loads.num_fds; i < nt && p->mem_loads.num_fds < MAX_THREADS; i++) {
        struct perf_event_attr pe = p->mem_loads.pe;
        int fd = perf_event_open(&pe, tids[i], -1, -1, 0);
        if (fd != -1) {
            ioctl(fd, PERF_EVENT_IOC_RESET, 0); ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
            p->mem_loads.fds[p->mem_loads.num_fds++] = fd;
        }
        if (p->dtlb_walks.num_fds > 0 && p->dtlb_walks.num_fds < MAX_THREADS) {
            pe = p->dtlb_walks.pe;
            fd = perf_event_open(&pe, tids[i], -1, -1, 0);
            if (fd != -1) {
                ioctl(fd, PERF_EVENT_IOC_RESET, 0); ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
                p->dtlb_walks.fds[p->dtlb_walks.num_fds++] = fd;
            }
        }
        if (p->dtlb_walk_completed.num_fds > 0 && p->dtlb_walk_completed.num_fds < MAX_THREADS) {
            pe = p->dtlb_walk_completed.pe;
            fd = perf_event_open(&pe, tids[i], -1, -1, 0);
            if (fd != -1) {
                ioctl(fd, PERF_EVENT_IOC_RESET, 0); ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
                p->dtlb_walk_completed.fds[p->dtlb_walk_completed.num_fds++] = fd;
            }
        }
    }
}

static int is_kernel_thread(pid_t pid) {
    char p[64]; snprintf(p, sizeof(p), "/proc/%d/cmdline", pid);
    FILE *f = fopen(p, "r");
    if (f) { int c = fgetc(f); fclose(f); return (c == EOF); }
    return 1;
}

static void get_process_name(pid_t pid, char *name, size_t len) {
    char p[64]; snprintf(p, sizeof(p), "/proc/%d/comm", pid);
    FILE *f = fopen(p, "r");
    if (f) { if (fgets(name, len, f)) { char *nl = strchr(name,'\n'); if (nl) *nl='\0'; } fclose(f); }
    else snprintf(name, len, "???");
}

static int get_page_faults(pid_t pid, long long *maj, long long *min) {
    char path[64], buf[1024];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    FILE *f = fopen(path, "r"); if (!f) return 0;
    *maj = 0; *min = 0;
    if (fgets(buf, sizeof(buf), f)) {
        char *p = strrchr(buf, ')');
        if (p) {
            long long mv, cm, jv, cj;
            if (sscanf(p+2, "%*c %*d %*d %*d %*d %*d %*u %lld %lld %lld %lld", &mv, &cm, &jv, &cj) == 4)
                { *min = mv; *maj = jv; fclose(f); return 1; }
        }
    }
    fclose(f); return 0;
}

static process_t *find_process(pid_t tgid) {
    for (int i = 0; i < num_procs; i++)
        if (procs[i].active && procs[i].tgid == tgid) return &procs[i];
    return NULL;
}

static pid_t get_tgid(pid_t pid) {
    char path[64], buf[256];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    FILE *f = fopen(path, "r"); if (!f) return pid;
    pid_t tgid = pid;
    while (fgets(buf, sizeof(buf), f)) if (sscanf(buf, "Tgid: %d", &tgid) == 1) break;
    fclose(f); return tgid;
}

static void add_process(pid_t pid) {
    pid_t tgid = get_tgid(pid);
    if (find_process(tgid) || tgid == daemon_pid || is_kernel_thread(tgid)) return;
    char name[32]; get_process_name(tgid, name, sizeof(name));
    if (is_system_process(name)) return;

    process_t *p = NULL;
    for (int i = 0; i < num_procs; i++) if (!procs[i].active) { p = &procs[i]; break; }
    if (!p) { if (num_procs >= MAX_PROCS) return; p = &procs[num_procs]; num_procs++; }

    memset(p, 0, sizeof(*p));
    p->tgid = tgid;
    init_counter(&p->mem_loads); init_counter(&p->dtlb_walks); init_counter(&p->dtlb_walk_completed);
    strncpy(p->name, name, sizeof(p->name)-1);

    if (!setup_process_counters(p)) return;

    p->prev_mem_loads_rd         = read_counter_full(&p->mem_loads);
    p->prev_dtlb_walks_rd       = (p->dtlb_walks.num_fds > 0) ? read_counter_full(&p->dtlb_walks) : (counter_reading_t){0,0,0};
    p->prev_dtlb_walk_completed_rd = (p->dtlb_walk_completed.num_fds > 0) ? read_counter_full(&p->dtlb_walk_completed) : (counter_reading_t){0,0,0};
    p->last_sample_time = get_time_ms();
    p->multiplex_pct = 100.0;

    get_page_faults(tgid, &p->prev_majflt, &p->prev_minflt);
    p->last_pf_sample_time = p->last_sample_time;
    p->active = 1;
}

static void cleanup_dead_processes(void) {
    for (int i = 0; i < num_procs; i++) {
        if (!procs[i].active) continue;
        if (kill(procs[i].tgid, 0) == -1 && errno == ESRCH) {
            if (procs[i].mitosis_enabled) mitosis_count--;
            close_counter(&procs[i].mem_loads);
            close_counter(&procs[i].dtlb_walks);
            close_counter(&procs[i].dtlb_walk_completed);
            procs[i].active = 0;
        }
    }
}

static void scan_processes(void) {
    DIR *d = opendir("/proc"); if (!d) return;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_type == DT_DIR || e->d_type == DT_UNKNOWN) {
            int is_num = 1;
            for (char *p = e->d_name; *p; p++) if (!isdigit(*p)) { is_num = 0; break; }
            if (is_num) add_process(atoi(e->d_name));
        }
    }
    closedir(d);
}

static void apply_steering_matrix(process_t *p) {
    if (!p->mitosis_enabled) return;
    prctl(PR_SET_PGTABLE_REPL_STEERING, steering_matrix, p->tgid, numa_node_count, 0);
}

static void enable_mitosis(process_t *p) {
    if (p->mitosis_enabled) return;
    unsigned long mask = build_node_bitmask();
    if (mask < 2) return;
    if (prctl(PR_SET_PGTABLE_REPL, mask, p->tgid, 0, 0) == 0) {
        p->mitosis_enabled = 1; mitosis_count++;
        apply_steering_matrix(p);
    }
}

static void disable_mitosis(process_t *p) {
    if (!p->mitosis_enabled) return;
    if (prctl(PR_SET_PGTABLE_REPL, 0, p->tgid, 0, 0) == 0) {
        p->mitosis_enabled = 0; mitosis_count--;
    }
}

static void update_and_decide(void) {
    double now = get_time_ms();

    for (int i = 0; i < num_procs; i++) {
        process_t *p = &procs[i];
        if (!p->active) continue;

        refresh_process_counters(p);

        counter_reading_t ml_rd  = read_counter_full(&p->mem_loads);
        counter_reading_t dw_rd  = (p->dtlb_walks.num_fds > 0)
                                     ? read_counter_full(&p->dtlb_walks)
                                     : (counter_reading_t){0,0,0};
        counter_reading_t dwc_rd = (p->dtlb_walk_completed.num_fds > 0)
                                     ? read_counter_full(&p->dtlb_walk_completed)
                                     : (counter_reading_t){0,0,0};

        long long d_mem       = scaled_delta(&ml_rd,  &p->prev_mem_loads_rd);
        long long d_walk      = scaled_delta(&dw_rd,  &p->prev_dtlb_walks_rd);
        long long d_walk_comp = scaled_delta(&dwc_rd, &p->prev_dtlb_walk_completed_rd);

        double elapsed_ms = now - p->last_sample_time;
        if (elapsed_ms < 1.0) elapsed_ms = 1.0;

        double worst_mux = 1.0;
        double r;
        r = mux_ratio(&ml_rd,  &p->prev_mem_loads_rd);  if (r < worst_mux) worst_mux = r;
        r = mux_ratio(&dw_rd,  &p->prev_dtlb_walks_rd); if (r < worst_mux) worst_mux = r;
        r = mux_ratio(&dwc_rd, &p->prev_dtlb_walk_completed_rd); if (r < worst_mux) worst_mux = r;
        p->multiplex_pct = worst_mux * 100.0;

        p->prev_mem_loads_rd         = ml_rd;
        p->prev_dtlb_walks_rd       = dw_rd;
        p->prev_dtlb_walk_completed_rd = dwc_rd;
        p->last_sample_time = now;

        p->last_mar = (double)d_mem * 1000.0 / elapsed_ms;

        if (d_mem > 0) {
            long long walks = (d_walk > 0) ? d_walk : d_walk_comp;
            p->last_dtlb_mr = (double)walks / (double)d_mem;
        } else {
            p->last_dtlb_mr = 0.0;
        }

        if (now - p->last_pf_sample_time >= PF_SAMPLE_INTERVAL) {
            long long majflt, minflt;
            if (get_page_faults(p->tgid, &majflt, &minflt)) {
                double pf_elapsed = now - p->last_pf_sample_time;
                long long df = (minflt - p->prev_minflt) + (majflt - p->prev_majflt);
                if (df < 0) df = 0;
                p->last_pf_rate = (double)df * 1000.0 / pf_elapsed;
                p->prev_majflt = majflt; p->prev_minflt = minflt;
                p->last_pf_sample_time = now;
            }
        }

        int above = (p->last_mar > THR_MAR) && (p->last_dtlb_mr > THR_DTLB);

        if (above) {
            p->below_threshold_since = 0;
            if (p->above_threshold_since == 0) p->above_threshold_since = now;
            if (!p->mitosis_enabled && (now - p->above_threshold_since) >= HYSTERESIS_MS)
                enable_mitosis(p);
        } else {
            p->above_threshold_since = 0;
            if (p->below_threshold_since == 0) p->below_threshold_since = now;
            if (p->mitosis_enabled && (now - p->below_threshold_since) >= HYSTERESIS_MS)
                disable_mitosis(p);
        }
    }
}

static void update_all_steering(void) {
    for (int i = 0; i < num_procs; i++)
        if (procs[i].active && procs[i].mitosis_enabled) apply_steering_matrix(&procs[i]);
}

static double get_process_priority(process_t *p) {
    if (p->mitosis_enabled) return 1e12;
    double mr = (THR_MAR > 0) ? p->last_mar / THR_MAR : 0;
    double dr = (THR_DTLB > 0) ? p->last_dtlb_mr / THR_DTLB : 0;
    double cl = mr * dr; if (cl > 0) cl = sqrt(cl);
    return cl * 1e6;
}

static int compare_proc_priority(const void *a, const void *b) {
    double pa = get_process_priority(&procs[*(const int*)a]);
    double pb = get_process_priority(&procs[*(const int*)b]);
    return (pb > pa) - (pb < pa);
}

static void format_node_mask(char *buf, size_t len) {
    int pos = 0, first = 1;
    for (int i = 0; i < numa_node_count; i++) {
        if (node_to_cpu_map[i] != -1) {
            if (!first && pos < (int)len - 2) buf[pos++] = ',';
            int w = snprintf(buf + pos, len - pos, "%d", i);
            if (w > 0) pos += w;
            first = 0;
        }
    }
    if (pos == 0 && len > 0) buf[0] = '\0';
    else if (pos < (int)len) buf[pos] = '\0';
}

static const char *event_label(void) {
    if (!use_raw_events) return "generic";
    if (cpu_vendor == 2)  return "raw AMD";
    if (cpu_vendor == 1) {
        switch (intel_arch) {
            case UARCH_SKX: return "raw SKX";
            case UARCH_ICX: return "raw ICX";
            case UARCH_SNB: return "raw SNB";
            case UARCH_HSW: return "raw HSW";
            default:        return "raw Intel";
        }
    }
    return "raw";
}

static void draw_header(void) {
    GOTO(1, 1);
    printf(BG_BLUE BOLD "  WASP - Workload-Aware Self-Replicating Page-Tables");
    for (int i = 52; i < term_cols; i++) printf(" ");
    printf(RESET);

    GOTO(2, 1);
    time_t now = time(NULL); struct tm *tm = localtime(&now);
    char nbuf[256];
    format_node_mask(nbuf, sizeof(nbuf));
    printf(DIM " CPU: %.2f GHz %s | Nodes: %d/%d {%s} | Hyst: %dms | %02d:%02d:%02d",
           cpu_ghz, uarch_name,
           active_node_count, numa_node_count, nbuf,
           HYSTERESIS_MS, tm->tm_hour, tm->tm_min, tm->tm_sec);
    printf(ESC "[K" RESET);

    GOTO(3, 1);
    if (mitosis_available) {
        printf(CYAN " Mitosis:" RESET " inherit=%s cache=%zuKB",
               (mitosis_inherit == 1) ? "on" : "off", cache_total_pages * 4);
    } else {
        printf(RED " Mitosis: kernel module not loaded" RESET);
    }
    printf("  " DIM "[%s events]" RESET, event_label());
    printf(ESC "[K");
}

static void draw_ptl_matrix(int sr) {
    GOTO(sr, 1);
    printf(BOLD " PTL Latency (ns)" RESET);
    if (ptl_measuring) printf(YELLOW " [measuring...]" RESET);
    else if (last_ptl_duration > 0) printf(DIM " [%.0fms]" RESET, last_ptl_duration);
    printf(ESC "[K");

    int row = sr + 1;
    GOTO(row, 1);
    printf(DIM "      ");
    for (int d = 0; d < numa_node_count; d++)
        if (node_to_cpu_map[d] != -1) printf(" %4d", d);
    printf(ESC "[K" RESET); row++;

    for (int s = 0; s < numa_node_count; s++) {
        if (node_to_cpu_map[s] == -1) continue;

        GOTO(row, 1); printf(DIM "  %2d:" RESET, s);
        double mn = 99999.0;
        for (int d = 0; d < numa_node_count; d++) {
            if (node_to_cpu_map[d] == -1) continue;
            double lat = ptl_matrix[s][d];
            if (lat > 0 && lat < mn) mn = lat;
        }
        for (int d = 0; d < numa_node_count; d++) {
            if (node_to_cpu_map[d] == -1) continue;
            double lat = ptl_matrix[s][d];
            int st = (steering_matrix[s] == d);
            if (lat == 0) printf(DIM "    -" RESET);
            else if (st) printf(GREEN BOLD " %4.0f" RESET, lat);
            else if (lat < mn * 1.5) printf(YELLOW " %4.0f" RESET, lat);
            else printf(RED " %4.0f" RESET, lat);
        }

        printf(ESC "[K"); row++;
    }

    row++;
    GOTO(row, 1); printf(CYAN " Steering:" RESET " ");
    for (int s = 0; s < numa_node_count; s++) {
        if (node_to_cpu_map[s] == -1) continue;
        int t = steering_matrix[s]; if (t >= 0 && t != s) printf("%d->%d ", s, t);
    }
    printf(ESC "[K");
}

static void draw_processes(int sr, int *er) {
    GOTO(sr, 1);
    printf(BOLD " Mitosis: %d" RESET " | tracking %d" ESC "[K", mitosis_count, num_procs);

    int row = sr + 1;
    GOTO(row, 1);
    printf(DIM "  %-7s %-10s %9s %6s %4s %5s %8s %8s" RESET ESC "[K",
           "PID", "Name", "MAR", "DTLB%", "Thr", "Mux%", "Status", "Hyst");
    row++;

    int sidx[MAX_PROCS], ac = 0;
    for (int i = 0; i < num_procs; i++) if (procs[i].active) sidx[ac++] = i;
    qsort(sidx, ac, sizeof(int), compare_proc_priority);

    int maxr = term_rows - 2;
    double now = get_time_ms();

    for (int j = 0; j < ac && row < maxr; j++) {
        process_t *p = &procs[sidx[j]];
        GOTO(row, 1);

        const char *status, *color;
        char hbuf[16] = "";

        if (p->mitosis_enabled) {
            status = "ACTIVE"; color = GREEN;
            if (p->below_threshold_since > 0) {
                int rem = HYSTERESIS_MS - (int)(now - p->below_threshold_since);
                if (rem > 0) snprintf(hbuf, sizeof(hbuf), "-%dms", rem);
            }
        } else {
            status = "watch"; color = DIM;
            if (p->above_threshold_since > 0) {
                int el = (int)(now - p->above_threshold_since);
                int rem = HYSTERESIS_MS - el;
                if (rem > 0) snprintf(hbuf, sizeof(hbuf), "+%dms", el);
            }
        }

        const char *mux_color;
        if (p->multiplex_pct >= 90.0)      mux_color = GREEN;
        else if (p->multiplex_pct >= 50.0) mux_color = YELLOW;
        else                               mux_color = RED;

        printf("  %s%-7d %-10.10s %9.2e %5.2f%% %4d" RESET
               " %s%4.0f%%" RESET
               " %s%8s %8s" RESET ESC "[K",
               color, p->tgid, p->name, p->last_mar, p->last_dtlb_mr * 100,
               p->mem_loads.num_fds,
               mux_color, p->multiplex_pct,
               color, status, hbuf);
        row++;
    }
    *er = row;
}

static void draw_footer(void) {
    GOTO(term_rows, 1);
    printf(BG_BLUE " q" RESET " Quit  "
           BG_BLUE " r" RESET " Remeasure  "
           BG_BLUE " c" RESET " Cache+100  "
           BG_BLUE " d" RESET " DrainCache  "
           BG_BLUE " m" RESET " ToggleMode");
    for (int i = 68; i < term_cols; i++) printf(" ");
}

static void draw_screen(void) {
    get_term_size(); printf(HOME CLEAR);
    draw_header();
    int mh = active_node_count + 3;
    draw_ptl_matrix(5);
    int er; draw_processes(5 + mh + 1, &er);
    for (int r = er; r < term_rows - 1; r++) { GOTO(r, 1); printf(ESC "[K"); }
    draw_footer(); fflush(stdout);
}

static void signal_handler(int sig) { (void)sig; stop_requested = 1; }

static void cleanup(void) {
    for (int i = 0; i < num_procs; i++) {
        if (!procs[i].active) continue;
        if (procs[i].mitosis_enabled) prctl(PR_SET_PGTABLE_REPL, 0, procs[i].tgid, 0, 0);
        close_counter(&procs[i].mem_loads);
        close_counter(&procs[i].dtlb_walks);
        close_counter(&procs[i].dtlb_walk_completed);
    }
    cleanup_ptl_buffers();
    if (mitosis_available) mitosis_set_inherit(1);
}

static void parse_node_mask(const char *arg) {
    memset(node_mask_enabled, 0, sizeof(node_mask_enabled));
    node_mask_set = 1;
    char buf[256];
    strncpy(buf, arg, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    char *tok = strtok(buf, ",");
    while (tok) {
        while (*tok == ' ') tok++;
        int n = atoi(tok);
        if (n >= 0 && n < MAX_NUMA_NODES)
            node_mask_enabled[n] = 1;
        tok = strtok(NULL, ",");
    }
}

static void print_usage(const char *prog) {
    printf("Usage: %s [options]\n", prog);
    printf("  -i N       PTL measurement interval in ms [default: %d]\n", PTL_UPDATE_INTERVAL);
    printf("  -u N       Main loop interval in ms [default: %d]\n", UPDATE_INTERVAL_MS);
    printf("  -y N       Hysteresis duration in ms [default: %d]\n", HYSTERESIS_MS);
    printf("  -c N       Pre-populate cache with N pages/node\n");
    printf("  -n M       Node mask: comma-separated list of nodes, e.g. 0,2,3 [default: all]\n");
    printf("  -g         Force generic HW_CACHE events (disable raw)\n");
    printf("  -h         Show this help\n");
}

int main(int argc, char *argv[]) {
    if (geteuid() != 0) {
        fprintf(stderr, "Error: waspd must be run as root (use sudo)\n");
        return 1;
    }

    int initial_cache = 0, force_generic = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0) { print_usage(argv[0]); return 0; }
        else if (strcmp(argv[i], "-i") == 0 && i+1 < argc) ptl_interval = atoi(argv[++i]);
        else if (strcmp(argv[i], "-u") == 0 && i+1 < argc) UPDATE_INTERVAL_MS = atoi(argv[++i]);
        else if (strcmp(argv[i], "-y") == 0 && i+1 < argc) HYSTERESIS_MS = atoi(argv[++i]);
        else if (strcmp(argv[i], "-c") == 0 && i+1 < argc) initial_cache = atoi(argv[++i]);
        else if (strcmp(argv[i], "-n") == 0 && i+1 < argc) parse_node_mask(argv[++i]);
        else if (strcmp(argv[i], "-g") == 0) force_generic = 1;
    }

    daemon_pid = getpid();

    cpu_vendor = detect_cpu_vendor();
    cpu_model  = detect_cpu_model();
    cpu_family = detect_cpu_family();
    classify_cpu();
    detect_cpu_freq();

    fprintf(stderr, "Detected: %s (family %d, model %d)\n", uarch_name, cpu_family, cpu_model);
    fprintf(stderr, "TSC frequency: %.3f GHz\n", cpu_ghz);

    if (cpu_vendor == 1 && intel_arch == UARCH_UNKNOWN) {
        fprintf(stderr, "Warning: unrecognized Intel model %d - raw events may not work.\n", cpu_model);
        fprintf(stderr, "         Use -g for generic events if you see problems.\n");
    }

    if (force_generic) { use_raw_events = 0; raw_events_tested = 1; }

    struct rlimit rlim = {65536, 65536};
    setrlimit(RLIMIT_NOFILE, &rlim);

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    init_topology();

    fprintf(stderr, "Detected %d NUMA node(s)\n", numa_node_count);

    apply_node_subset();
    active_node_count = count_active_nodes();

    if (active_node_count < 2) {
        fprintf(stderr, "Error: need >= 2 active NUMA nodes (found %d)\n", active_node_count);
        return 1;
    }

    if (node_mask_set) {
        char nbuf[256];
        format_node_mask(nbuf, sizeof(nbuf));
        fprintf(stderr, "Node mask: {%s} (%d nodes)\n", nbuf, active_node_count);
    }

    init_ptl_buffers();
    if (!ptl_buffers_ready)
        fprintf(stderr, "Warning: PTL buffer allocation failed - latency measurement disabled\n");

    mitosis_available = mitosis_check_available();
    if (mitosis_available) {
        mitosis_update_status();
        mitosis_set_inherit(0);
        if (initial_cache > 0) mitosis_populate_cache(initial_cache);
    } else {
        fprintf(stderr, "Warning: %s not found - kernel module may not be loaded\n", MITOSIS_PROC_DIR);
    }

    term_init();
    last_ptl_update = 0;

    while (!stop_requested) {
        char c;
        if (read(STDIN_FILENO, &c, 1) == 1) {
            if (c == 'q' || c == 'Q') break;
            if (c == 'r' || c == 'R') last_ptl_update = 0;
            if ((c == 'c' || c == 'C') && mitosis_available) mitosis_populate_cache(100);
            if ((c == 'd' || c == 'D') && mitosis_available) mitosis_drain_cache();
            if ((c == 'm' || c == 'M') && mitosis_available) mitosis_set_mode((mitosis_mode+2)%3-1);
        }

        cleanup_dead_processes();
        scan_processes();

        double old = last_ptl_update;
        update_ptl_matrix();
        if (last_ptl_update != old) update_all_steering();

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
