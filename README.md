# WASP - Workload-Aware Self-Replicating Page-Tables

A userspace daemon with TUI that automatically manages page table replication across NUMA nodes using the Mitosis kernel module.

## Overview

WASP monitors running processes and dynamically enables page table replication for memory-intensive workloads. It measures cross-node page table lookup latencies and computes an optimal steering matrix to direct lookups to the fastest replica.

This implementation is based on the research paper:

> **WASP: Workload-Aware Self-Replicating Page-Tables for NUMA Systems**  
> Hongliang Qu, Zhibin Yu  
> *ASPLOS '24*  
> DOI: [10.1145/3620665.3640369](https://doi.org/10.1145/3620665.3640369)

The paper proposes replicating page tables across NUMA nodes and steering TLB miss handling to the optimal replica based on measured access latencies, reducing remote memory accesses during page table walks.

## Features

- **Automatic Process Detection**: Discovers and monitors user processes, filtering out system/kernel threads
- **Performance Counter Monitoring**: Tracks memory access rates (MAR) and dTLB miss ratios per process
- **Dynamic Mitosis Control**: Enables/disables page table replication based on configurable thresholds with hysteresis
- **PTL Latency Measurement**: Periodically measures page table lookup latencies across all NUMA node pairs
- **Steering Matrix Computation**: Automatically calculates optimal replica targets for each physical node
- **Interactive TUI**: Real-time visualization of system state, latency matrix, and process metrics

## Requirements

- Linux kernel with Mitosis page table replication support
- Mitosis kernel module loaded (provides `/proc/mitosis/*` interfaces)
- Multi-socket NUMA system (≥2 nodes)
- Root privileges (for perf counters and prctl calls)
- perf_event support in kernel

## Building

```bash
gcc -O2 -o waspd waspd.c -lm
```

## Usage

```bash
sudo ./waspd [options]
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-i N` | PTL measurement interval in milliseconds | 1000 |
| `-u N` | Main loop update interval in milliseconds | 1000 |
| `-y N` | Hysteresis duration in milliseconds | 1000 |
| `-c N` | Pre-populate page table cache with N pages per node | 0 |
| `-h` | Show help message | — |

### Interactive Commands

| Key | Action |
|-----|--------|
| `q` | Quit |
| `r` | Force PTL remeasurement |
| `c` | Add 100 pages per node to cache |
| `d` | Drain the page table cache |
| `m` | Toggle Mitosis mode |

## How It Works

1. **Process Discovery**: Scans `/proc` for user processes, excluding kernel threads and system daemons (shells, ssh, systemd, etc.)

2. **Performance Monitoring**: Uses hardware performance counters to track:
   - Memory Access Rate (MAR): L1D cache read accesses per second
   - dTLB Miss Ratio: Fraction of dTLB accesses that miss

3. **Threshold-Based Activation**: A process becomes a candidate for Mitosis when:
   - MAR exceeds 10M accesses/second
   - dTLB miss ratio exceeds 1%
   - Both conditions sustained for the hysteresis period

4. **PTL Latency Measurement**: Forks a child process that:
   - Allocates memory bound to each NUMA node
   - Measures memory access latency from each source node to each destination node
   - Results form the PTL latency matrix

5. **Steering Matrix Computation**: For each physical node, selects the replica node with lowest measured latency

6. **Mitosis Control**: Uses `prctl()` system calls to:
   - Enable/disable page table replication per process (`PR_SET_PGTABLE_REPL`)
   - Configure the steering matrix (`PR_SET_PGTABLE_REPL_STEERING`)

## Kernel Interface

WASP communicates with the Mitosis kernel module via:

### Proc Filesystem (`/proc/mitosis/`)

| File | Description |
|------|-------------|
| `status` | Overall Mitosis status |
| `active` | Number of processes with active replication |
| `mode` | Global replication mode |
| `inherit` | Whether children inherit replication settings |
| `cache` | Page table cache statistics; write to populate/drain |

### Prctl Commands

| Command | Description |
|---------|-------------|
| `PR_SET_PGTABLE_REPL (100)` | Enable/disable replication for a process |
| `PR_GET_PGTABLE_REPL (101)` | Query replication status |
| `PR_SET_PGTABLE_REPL_STEERING (104)` | Set steering matrix for a process |
| `PR_GET_PGTABLE_REPL_STEERING (105)` | Query steering matrix |

## Configuration

Key compile-time constants in `waspd.c`:

```c
#define NUMA_NODE_COUNT 8       // Must match kernel's mm_types.h
#define THR_MAR  10.0 * 1e6     // MAR threshold (accesses/sec)
#define THR_DTLB 0.01           // dTLB miss ratio threshold (1%)
#define PTL_ITERATIONS 10       // Iterations per latency measurement
#define PTL_PAGES 64            // Pages allocated for measurement
```

## TUI Display

```
  WASP - Workload-Aware Self-Replicating Page-Tables
  CPU: 2.80 GHz | Nodes: 4 | Hyst: 1000ms | 14:32:01
  Mitosis: inherit=off cache=1600KB

  PTL Latency Matrix (ns) [42ms]
        0    1    2    3
    0:  85  142  198  201
    1: 145   83  203  195
    2: 201  198   87  140
    3: 195  202  143   84

  Steering: 0->0 1->1 2->2 3->3

  Mitosis: 2 | tracking 5
    PID    Name         MAR  DTLB%   Status     Hyst
    12345  benchmark  1.5e+07  2.31%   ACTIVE
    12400  worker     8.2e+06  1.82%   watch   +450ms
    ...
```

## License

See source file for licensing information.

## References

- [WASP Paper (ACM DL)](https://dl.acm.org/doi/10.1145/3620665.3640369)
- [Mitosis: Transparently Self-Replicating Page-Tables](https://doi.org/10.1145/3373376.3378468) - Related work on the Mitosis kernel infrastructure
