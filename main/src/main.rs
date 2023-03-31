mod bpf {
    include!(concat!(env!("OUT_DIR"), "/prog.bpf.rs"));
}
mod common;
mod tui;

use std::{time::{Duration, Instant}, thread};
use anyhow::anyhow;
use libbpf_rs::{MapFlags, num_possible_cpus};
use powercap::PowerCap;
use tui::Tui;

fn main() -> anyhow::Result<()> {
    let open_skel = bpf::ProgSkelBuilder::default().open()?;
    let mut skel = open_skel.load()?;

    // Explicitly attach entry programs last (because the task-local storage can only be allocated by them)
    let _sched_switch_link = skel.progs_mut().tp_sched_switch().attach()?;
    let _sock_send_exit_link = skel.progs_mut().send_msg_exit().attach()?;
    let _net_rx_softirq_exit_link = skel.progs_mut().net_rx_softirq_exit().attach()?;
    let _sock_send_entry_link = skel.progs_mut().send_msg_entry().attach()?;
    let _net_rx_softirq_entry = skel.progs_mut().net_rx_softirq_entry().attach()?;

    // let _br_handle_frame_entry = skel.progs_mut().br_handle_frame_entry().attach()?;

    let maps = skel.maps();
    let per_cpu_map = maps.per_cpu();

    let rapl = PowerCap::try_default()
        .map_err(|_| anyhow!("RAPL: Failed to open powercap interface from /sys/class/powercap"))?
        .intel_rapl;

    let num_possible_cpus = num_possible_cpus()?;
    let mut prev_total_times = vec![vec![0u64; 6]; num_possible_cpus];
    let mut prev_instant = Instant::now();

    let mut prev_total_energy = 0;

    let num_possible_cpus = num_possible_cpus;
    let (mut tui_runnable, mut tui) = Tui::init(num_possible_cpus);
    let mut tui_runner = tui_runnable.runner();

    while tui_runner.is_running() {
        thread::sleep(Duration::from_millis(500));
        let current_instant = Instant::now();
        let delta_time = current_instant.duration_since(prev_instant);
        prev_instant = current_instant;

        let current_total_energy = rapl
            .sockets
            .values()
            .flat_map(|socket| socket.energy())
            .sum();
        let delta_energy = current_total_energy - prev_total_energy;
        prev_total_energy = current_total_energy;

        if let Some(stats) = per_cpu_map.lookup_percpu(&0i32.to_le_bytes(), MapFlags::empty())? {
            stats
                .iter()
                .zip(prev_total_times.iter_mut())
                .enumerate()
                .map(|(cpuid, (cpu_stats, prev_total_cpu_times))| {
                    let mut total_cpu_frac = 0.0;
                    
                    let mut cpu_times = unsafe {
                        &*(cpu_stats.as_ptr() as *const common::per_cpu_data)
                    }.events
                        .iter()
                        .zip(prev_total_cpu_times.iter_mut())
                        .enumerate()
                        .map(|(event_idx, (common::per_event_data { total_time, .. }, prev_total_time))| {
                            let delta_cpu_time = total_time - *prev_total_time;
                            *prev_total_time = *total_time;
                            let cpu_frac = (delta_cpu_time as f64) / (delta_time.as_nanos() as f64);

                            let metric_name = match event_idx {
                                0 /* EVENT_SOCK_SENDMSG   */ => {
                                    total_cpu_frac += cpu_frac;
                                    "tx_syscalls"
                                },
                                1 /* EVENT_NET_RX_SOFTIRQ */ => {
                                    total_cpu_frac += cpu_frac;
                                    "rx_softirq"
                                },
                                2 /* EVENT_CONSUME_SKB    */ => "",
                                3 /* EVENT_BRDIGE         */ => "bridging",
                                4 /* EVENT_FORWARD        */ => "forwarding",
                                5 /* EVENT_LOCAL_DELIVER  */ => "",

                                _ => unreachable!()
                            };

                            let _ = tui.set_val(cpuid, metric_name, cpu_frac);

                            cpu_frac
                        })
                        .collect::<Vec<_>>();

                    cpu_times.push(total_cpu_frac);
                    let _ = tui.set_val(cpuid, "total", total_cpu_frac);

                    cpu_times
                })
                .reduce(|mut acc, e| {
                    acc
                        .iter_mut()
                        .zip(e.iter())
                        .for_each(|(acc, e)| {
                            *acc += *e;
                        });

                    acc
                })
                .unwrap()
                .iter()
                .enumerate()
                .for_each(|(event_idx, e)| {
                    let cpu_frac = e / (num_possible_cpus as f64);
                    
                    let metric_name = match event_idx {
                        0 /* EVENT_SOCK_SENDMSG   */ => "tx_syscalls",
                        1 /* EVENT_NET_RX_SOFTIRQ */ => "rx_softirq",
                        2 /* EVENT_CONSUME_SKB    */ => "",
                        3 /* EVENT_BRDIGE         */ => "bridging",
                        4 /* EVENT_FORWARD        */ => "forwarding",
                        5 /* EVENT_LOCAL_DELIVER  */ => "",

                        6 /* TOTAL */                => {
                            tui.set_total_power(((delta_energy as f64) * cpu_frac) / (delta_time.as_secs_f64() * 1_000_000.0));
                            "total"
                        },

                        _ => unreachable!()
                    };

                    let _ = tui.set_val(num_possible_cpus, metric_name, cpu_frac);
                });
        }
        
        tui_runner.refresh();
        tui_runner.step();
    }

    Ok(())
}
