# waspd: Workload-Aware Page Table Replication Daemon

Userspace daemon that monitors running processes via hardware performance counters and automatically enables or disables [Mitosis](https://github.com/julianw1010/WASP-linux-6.4.0) page table replication based on workload characteristics. Also measures inter-node memory access latency and steers each node's page table replica selection toward the lowest-latency option.

Implements the WASP approach described by Qu and Yu (ASPLOS '24), adapted for the Mitosis kernel patch on Linux 6.4.

## Requirements

- Linux kernel with the [Mitosis patch](https://github.com/julianw1010/WASP-linux-6.4.0) applied (provides `/proc/mitosis/` and `PR_SET_PGTABLE_REPL`)
- At least 2 NUMA nodes
- Root privileges (for `perf_event_open` and `prctl` on other processes)
- x86_64: Intel Sandy Bridge or later, AMD Zen or later

## Building

```bash
gcc -O2 -o waspd waspd.c -lm
```

## Usage

```bash
sudo ./waspd [options]
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-i N` | PTL latency measurement interval (ms) | 1000 |
| `-u N` | Main loop / sampling interval (ms) | 1000 |
| `-y N` | Hysteresis duration before enable/disable (ms) | 1000 |
| `-c N` | Pre-populate Mitosis page table cache with N pages per node | 0 |
| `-n M` | Restrict to specific NUMA nodes (comma-separated, e.g. `0,2,3`) | all |
| `-g` | Force generic `HW_CACHE` events instead of architecture-specific raw events | off |
| `-h` | Show help | |

### Examples

```bash
# Default: monitor all nodes, 1s intervals
sudo ./waspd

# Only use nodes 0 and 1, 500ms hysteresis
sudo ./waspd -n 0,1 -y 500

# Pre-populate cache, measure latency every 5s
sudo ./waspd -c 200 -i 5000

# Force generic perf events (useful on unrecognized CPU models)
sudo ./waspd -g
```

## How It Works

### Process monitoring

waspd scans `/proc` for running user processes, skipping kernel threads and a built-in blacklist of system processes (shells, editors, service daemons, etc.). Each tracked process gets per-thread perf counters attached via `perf_event_open`. New threads are picked up on subsequent scan cycles.

### Decision logic

Each sampling interval, waspd computes two metrics per process:

**MAR** (Memory Access Rate): memory load events per second.

**dTLB miss ratio**: page table walk events divided by memory load events.

A process is above threshold when MAR exceeds 10M/s and the dTLB miss ratio exceeds 1%. Replication is enabled only after the process remains above threshold for the full hysteresis duration, and disabled only after it remains below for the same duration. This prevents toggling when metrics fluctuate near the boundary.

### PTL latency measurement

waspd periodically forks a child process that pins itself to each source node in turn, then times `clflush` + reload of cache lines in buffers bound (via `mbind`) to each destination node. The cycle count is converted to nanoseconds using the calibrated TSC frequency. The result is an N x N latency matrix.

### Steering

After each latency measurement, waspd computes a steering table: for each physical node, the replica node with the lowest measured access latency. This is pushed to the kernel via `prctl(PR_SET_PGTABLE_REPL_STEERING)` for every replicated process. When co-located workloads cause local memory controller contention, the lowest-latency path may go through a remote node rather than the local one.

### Performance counter selection

Architecture-specific raw PMU events are used where available:

| Vendor / uarch | Memory loads event | dTLB walk event |
|----------------|-------------------|-----------------|
| Intel SKX/ICX+ | `MEM_LOAD_RETIRED.L1_HIT` | `DTLB_LOAD_MISSES.MISS_CAUSES_A_WALK` |
| Intel SNB/HSW | `MEM_LOAD_RETIRED.L1_HIT` | `DTLB_LOAD_MISSES.MISS_CAUSES_A_WALK` |
| AMD Zen+ | `LS_DISPATCH.LOADS` | `L1_DTLB_MISS` |
| Generic fallback | `HW_CACHE_L1D` read access | `HW_CACHE_DTLB` read miss |

Counter multiplexing is tracked per process. The TUI displays the multiplexing percentage so the operator can assess data quality.

## Interactive Controls

waspd runs in an alternate terminal buffer with a live TUI.

| Key | Action |
|-----|--------|
| `q` | Quit |
| `r` | Re-measure PTL latency matrix |
| `c` | Populate Mitosis cache (+100 pages per node) |
| `d` | Drain Mitosis cache |
| `m` | Cycle Mitosis mode (`-1` / `0` / `1`) |

### TUI layout

```
  WASP - Workload-Aware Self-Replicating Page-Tables
  CPU: 2.10 GHz Skylake-SP | Nodes: 2/2 {0,1} | Hyst: 1000ms | 14:32:01
  Mitosis: inherit=off cache=800KB  [raw SKX events]

  PTL Latency (ns) [142ms]
           0    1
    0:   42  110
    1:  108   41
  Steering: (all local)

  Mitosis: 1 | tracking 3
    PID    Name          MAR  DTLB%  Thr  Mux%   Status     Hyst
    1234   myapp     1.52e+07  2.31%    8  100%   ACTIVE
    5678   worker    3.20e+06  0.42%    4   98%    watch
    9012   loader    8.10e+05  0.08%    2   95%    watch
```

The top section shows CPU info, active nodes, and Mitosis kernel state. The PTL matrix shows measured latencies in nanoseconds between all node pairs, with the steered (selected) entries highlighted. The process table shows each tracked process sorted by proximity to the activation threshold.

## Supported CPUs

| CPU | Raw events | Status |
|-----|-----------|--------|
| Intel Sandy Bridge / Ivy Bridge | SNB encoding | Tested |
| Intel Haswell / Broadwell | HSW encoding | Tested |
| Intel Skylake / Skylake-SP | SKX encoding | Tested |
| Intel Ice Lake-SP / Sapphire Rapids / Emerald Rapids | ICX encoding | Tested |
| AMD Zen / Zen 2 (Family 17h) | AMD encoding | Tested |
| AMD Zen 3 / Zen 4 (Family 19h) | AMD encoding | Tested |
| Other | Generic `HW_CACHE` fallback (`-g`) | Less precise |

## References

Achermann, R., Panwar, A., Bhattacharjee, A., Roscoe, T., and Gandhi, J. (2020). *Mitosis: Transparently Self-Replicating Page-Tables for Large-Memory Machines.* ASPLOS '20, pp. 283-300. [doi:10.1145/3373376.3378468](https://doi.org/10.1145/3373376.3378468)

Wang, J., Wang, Z., Li, Y., Chen, L., and Li, J. (2024). *WASP: Workload-Aware Self-Replicating Page-Tables for NUMA Servers.* ASPLOS '24, Vol. 2, pp. 214-229. [doi:10.1145/3620665.3640369](https://doi.org/10.1145/3620665.3640369)

Mitosis kernel patch (Linux 6.4): https://github.com/julianw1010/WASP-linux-6.4.0

Original Mitosis implementation (Linux 4.17): https://github.com/julianw1010/mitosis-linux

## License

GPL-2.0
