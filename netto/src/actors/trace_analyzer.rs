use std::time::{Duration, Instant};
use actix::{Actor, Context, AsyncContext, Addr};
use anyhow::anyhow;
use libbpf_rs::MapFlags;
use powercap::{IntelRapl, PowerCap};
use tokio::sync::mpsc::Sender;
use crate::{ksyms::{Counts, KSyms, Metric}, common::{event_types_EVENT_MAX, self, event_types_EVENT_SOCK_SENDMSG, event_types_EVENT_NET_TX_SOFTIRQ, event_types_EVENT_NET_RX_SOFTIRQ, event_types_EVENT_SOCK_RECVMSG, event_types_EVENT_IO_WORKER}, bpf::ProgSkel};
use libc::{mmap, PROT_READ, MAP_SHARED, sysconf, _SC_CLK_TCK};
use super::{metrics_collector::MetricsCollector, MetricUpdate, SubmitUpdate};
#[cfg(feature = "save-traces")]
use std::fs::File;

pub struct MetricSender {
    /// Addr of the `MetricsCollector` actor
    metrics_collector_addr: Addr<MetricsCollector>,
    cpuid: usize,
    cpu_frac: f64,
    denominator: f64
}

impl MetricSender {
    pub fn send_metrics(&self, prefix: String, parent_metric: &Metric, sub_value: u16) {
        self.metrics_collector_addr.do_send(MetricUpdate {
            clear: false,
            name: prefix.clone(),
            cpuid: self.cpuid,
            cpu_frac: self.cpu_frac * (parent_metric.count - sub_value) as f64 / self.denominator
        });
        self.send_sub_metrics(prefix.clone(), parent_metric, sub_value);
    }

    pub fn send_sub_metrics(&self, prefix: String, parent_metric: &Metric, sub_value: u16) {
        parent_metric.sub_metrics
            .iter()
            .map(|(name, sub_metric)| {
                let formatted_name = format!("{}/{}", prefix, name);

                let mut count_value = 0;
                if sub_metric.count > sub_value {
                    count_value = sub_metric.count - sub_value;
                }

                self.metrics_collector_addr.do_send(MetricUpdate {
                    clear: false,
                    name: formatted_name.clone(),
                    cpuid: self.cpuid,
                    cpu_frac: self.cpu_frac * count_value as f64  / self.denominator
                });

                self.send_sub_metrics(formatted_name.clone(), sub_metric, sub_value);

                sub_metric.count as f64
            })
            .sum::<f64>();
    }
}

/// Actor responsible for interacting with BPF via shared maps,
/// retrieve stack traces from the ring buffer, and analyze them
/// to provide user-facing performance metrics.
pub struct TraceAnalyzer {
    /// User-space invocation period in ms
    run_interval_ms: u64,

    /// libbpf's skeleton
    skel: ProgSkel<'static>,

    /// Pointer to the mmaped stack traces array map
    stack_traces_ptr: *const u64,

    /// Half size of the `stack_traces` eBPF map in number of entries
    stack_traces_slot_size: u32,

    /// Vec of one Counts for each CPU
    counts: Vec<Counts>,

    /// Kernel symbols for processing the traces
    ksyms: KSyms,

    /// Link to the open powercap interface for power queries
    rapl: Option<IntelRapl>,

    /// USER_HZ for reading /proc/stat
    ticks_per_second: f64,

    procfs_metrics_old: Vec<i64>,

    /// Addr of the `MetricsCollector` actor
    metrics_collector_addr: Addr<MetricsCollector>,

    /// Interface for sending unrecoverable runtime errors to the
    /// main task, triggering the program termination
    error_catcher_sender: Sender<anyhow::Error>,

    // State-keeping fields

    /// Timestamp of the previous update cycle.
    /// Useful to calculate the delta-time.
    prev_update_ts: Instant,

    /// Total times up to the previous update cycle,
    /// for each cpu for each event
    prev_total_times: Vec<Vec<u64>>,

    /// Total energy, as reported by RAPL, up to the
    /// previous update cycle
    prev_total_energy: u64,

    #[cfg(feature = "save-traces")]
    traces_output_buf: Vec<u8>
}

impl TraceAnalyzer {
    /// Build a new TraceAnalyzer instance.
    ///
    /// Note that the `per_cpu` map is passed by its id in order
    /// to be able to acquire it as an owned `libbpf_rs::Map` and
    /// avoid the reference to the lifetime of the main skel.
    pub fn new(
        run_interval_ms: u64,
        skel: ProgSkel<'static>,
        num_possible_cpus: usize,
        stack_traces_max_entries: u32,
        metrics_collector_addr: Addr<MetricsCollector>,
        error_catcher_sender: Sender<anyhow::Error>
    ) -> anyhow::Result<Self> {
        let stack_traces_ptr = unsafe { mmap(
            std::ptr::null_mut(),
            std::mem::size_of::<u64>() * 128 * stack_traces_max_entries as usize,
            PROT_READ,
            MAP_SHARED,
            skel.maps().stack_traces().fd(),
            0
        ) } as *const u64;

        let rapl = PowerCap::try_default()
            .map(|rapl| rapl.intel_rapl)
            .ok();

        let ticks_per_second = unsafe {
            let v = sysconf(_SC_CLK_TCK);
            if v < 0 {
                anyhow::bail!("Failed to retrieve ticks per second from sysconf");
            }
            v as f64
        };

        Ok(Self {
            run_interval_ms,
            skel,
            stack_traces_ptr,
            stack_traces_slot_size: stack_traces_max_entries / 2,
            counts: vec![Counts::default(); num_possible_cpus],
            ksyms: KSyms::load()?,
            ticks_per_second,
            procfs_metrics_old: vec![0; 10], // TODO: make this agnostic to the actual number of metrics in procfs
            rapl,
            metrics_collector_addr,
            error_catcher_sender,
            prev_update_ts: Instant::now(),
            prev_total_times: vec![vec![0;  event_types_EVENT_MAX as _]; num_possible_cpus],
            prev_total_energy: 0,
            #[cfg(feature = "save-traces")]
            traces_output_buf: vec![]
        })
    }

    /// Main user-space update loop
    #[inline]
    fn run_interval(&mut self) -> anyhow::Result<()> {
        let now = Instant::now();

        self.metrics_collector_addr.do_send(MetricUpdate {
            clear: true,
            name: "".to_owned(),
            cpuid: 0,
            cpu_frac: 0.0
        });

        // Update state
        let delta_time = {
            let dt = now.duration_since(self.prev_update_ts);
            self.prev_update_ts = now;
            dt
        };
        let delta_energy = self.rapl.as_ref().map(|rapl| {
            let current_total_energy = rapl
                .sockets
                .values()
                .flat_map(|socket| socket.energy())
                .sum();
            let delta_energy = current_total_energy - self.prev_total_energy;
            self.prev_total_energy = current_total_energy;
            delta_energy
        });

        // Reset counts to zero
        for counts in &mut self.counts {
            *counts = Counts::default();
        }

        // Drain the stack traces array
        {
            // Swap buffer slots and get the number of stack traces in the previously active slot
            let slot_off = self.skel.bss().stack_traces_slot_off as usize;
            let num_traces_ref;
            (self.skel.bss().stack_traces_slot_off, num_traces_ref) = if slot_off > 0 {
                (0                          , &mut self.skel.bss().stack_traces_count_slot_1)
            } else {
                (self.stack_traces_slot_size, &mut self.skel.bss().stack_traces_count_slot_0)
            };

            // Make sure to read the count *after* swapping the slots
            let num_traces = *num_traces_ref;

            // Count symbols
            unsafe {
                for trace_ptr in (0..num_traces as usize).map(|trace_idx| self.stack_traces_ptr.add((slot_off + trace_idx) * 128 /* size of a single trace */)) {
                    // Get the cpuid
                    let (trace_size, cpuid) = {
                        let v = trace_ptr.read_volatile();

                        // Note that the trace size is encoded in bytes in the map, but we care about number of u64s
                        (v >> 35, v & 0xFFFFFFFF)
                    };

                    self.counts[cpuid as usize].acc_trace(
                        &self.ksyms,
                        trace_ptr.add(1),
                        trace_size as _,
                        #[cfg(feature = "save-traces")]
                        &mut self.traces_output_buf
                    );
                }
            }

            // Reset the stack traces index for this slot
            *num_traces_ref = 0;
        }

        // Get a reference to the counts
        let counts = &self.counts;

        // Lookup in the per-cpu map
        let stats = self.skel.maps().per_cpu()
            .lookup_percpu(&0i32.to_le_bytes(), MapFlags::empty())?
            .ok_or(anyhow!("Unexpected None returned for lookup into the \"per_cpu\" map"))?;

        let total_cpu_frac = stats
            .iter()
            .zip(self.prev_total_times.iter_mut())
            .enumerate()
            .map(|(cpuid, (cpu_stats, prev_total_cpu_times))| {
                unsafe {
                    // Read the data as unaligned because we do not have any alignment guarantees at this point
                    (cpu_stats.as_ptr() as *const common::per_cpu_data).read_unaligned()
                }.per_event_total_time
                    .iter()
                    .zip(prev_total_cpu_times.iter_mut())
                    .enumerate()
                    .map(|(event_idx, (total_time, prev_total_time))| {
                        let delta_cpu_time = total_time - *prev_total_time;
                        *prev_total_time = *total_time;
                        let cpu_frac = (delta_cpu_time as f64) / (delta_time.as_nanos() as f64);

                        #[allow(non_upper_case_globals)]
                        let metric_name = match event_idx as u32 {
                            event_types_EVENT_SOCK_SENDMSG   => "TX syscalls",
                            event_types_EVENT_SOCK_RECVMSG   => "RX syscalls",
                            event_types_EVENT_NET_TX_SOFTIRQ => "TX softirq",
                            event_types_EVENT_IO_WORKER      => "IO workers",
                            event_types_EVENT_NET_RX_SOFTIRQ => {
                                // Update sub-events
                                let denominator = counts[cpuid].net_rx_action.count.max(1) as f64;

                                let metrics_sender = MetricSender {
                                    metrics_collector_addr: self.metrics_collector_addr.clone(),
                                    cpuid,
                                    cpu_frac,
                                    denominator
                                };

                                // Driver poll
                                metrics_sender.send_metrics(
                                    String::from("RX softirq/Driver poll"),
                                    &counts[cpuid].__napi_poll,
                                    counts[cpuid].netif_receive_skb.count
                                );

                                // GRO overhead
                                metrics_sender.send_metrics(
                                    String::from("RX softirq/GRO overhead"),
                                    &counts[cpuid].napi_gro_receive_overhead,
                                    0
                                );

                                // XDP generic
                                metrics_sender.send_metrics(
                                    String::from("RX softirq/XDP generic"),
                                    &counts[cpuid].do_xdp_generic,
                                    0
                                );

                                // TC classify
                                metrics_sender.send_metrics(
                                    String::from("RX softirq/TC classify"),
                                    &counts[cpuid].tcf_classify,
                                    0
                                );

                                // NF ingress
                                metrics_sender.send_metrics(
                                    String::from("RX softirq/NF ingress"),
                                    &counts[cpuid].nf_netdev_ingress,
                                    0
                                );

                                // Conntrack
                                metrics_sender.send_metrics(
                                    String::from("RX softirq/NF conntrack"),
                                    &counts[cpuid].nf_conntrack_in,
                                    0
                                );

                                // Bridging
                                metrics_sender.send_metrics(
                                    String::from("X softirq/Bridging"),
                                    &counts[cpuid].br_handle_frame,
                                    counts[cpuid].netif_receive_skb_sub_br.count
                                );

                                // NF prerouting
                                metrics_sender.send_metrics(
                                    String::from("RX softirq/NF prerouting/v4"),
                                    &counts[cpuid].nf_prerouting_v4,
                                    0
                                );

                                metrics_sender.send_metrics(
                                    String::from("RX softirq/NF prerouting/v6"),
                                    &counts[cpuid].nf_prerouting_v6,
                                    0
                                );

                                // Forwarding
                                metrics_sender.send_metrics(
                                    String::from("RX softirq/Forwarding/v4"),
                                    &counts[cpuid].ip_forward,
                                    0
                                );

                                metrics_sender.send_metrics(
                                    String::from("RX softirq/Forwarding/v6"),
                                    &counts[cpuid].ip6_forward,
                                    0
                                );

                                // Local deliver
                                metrics_sender.send_metrics(
                                    String::from("RX softirq/Local delivery/v4"),
                                    &counts[cpuid].ip_local_deliver,
                                    0
                                );

                                metrics_sender.send_metrics(
                                    String::from("RX softirq/Local delivery/v6"),
                                    &counts[cpuid].ip6_input,
                                    0
                                );

                                "RX softirq"
                            },
                            _ => unreachable!()
                        };

                        self.metrics_collector_addr.do_send(MetricUpdate {
                            clear: false,
                            name: metric_name.to_owned(),
                            cpuid,
                            cpu_frac
                        });

                        cpu_frac
                    })
                    .sum::<f64>()
            })
            .sum::<f64>() / (self.prev_total_times.len() as f64);

        // Collect /proc/stat metrics
        let procfs_metrics = std::fs::read_to_string("/proc/stat")?
            .lines()
            .take(1)
            .flat_map(|s| {
                s.split_ascii_whitespace()
                    .skip(1)
                    .map(|s| s.parse::<i64>().unwrap())
            })
            .zip(self.procfs_metrics_old.iter_mut())
            .map(|(curr, old)| {
                let delta = curr - *old;
                *old = curr;
                (delta as f64) / (self.ticks_per_second * delta_time.as_secs_f64())
            })
            .collect::<Vec<_>>();

        self.metrics_collector_addr.do_send(SubmitUpdate {
            net_power_w: delta_energy.map(|e| (e as f64) * total_cpu_frac / (delta_time.as_secs_f64() * 1_000_000.0)),
            user_space_overhead: now.elapsed().as_secs_f64() / delta_time.as_secs_f64(),
            procfs_metrics
        });

        Ok(())
    }
}

impl Actor for TraceAnalyzer {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.run_interval(Duration::from_millis(self.run_interval_ms), |act, _| {
            if let Err(e) = act.run_interval() {
                act.error_catcher_sender.blocking_send(e).unwrap();
            }
        });
    }

    #[cfg(feature = "save-traces")]
    fn stopped(&mut self, _ctx: &mut Self::Context) {
        use std::io::Write;
        let mut traces_file = File::create("traces").unwrap();
        traces_file.write_all(&self.traces_output_buf).unwrap();
    }
}
