#[cfg(feature = "save-traces")]
use std::io::Write;
use std::{
    collections::BTreeMap,
    fs::File,
    io::{self, BufRead, BufReader},
    iter::Sum,
    ops::{Add, AddAssign, Bound},
};

use clap::Parser;

use crate::Cli;

/// Helper to load and manage application-defined kernel symbols
#[derive(Default)]
pub struct KSyms {
    syms: BTreeMap<u64, KSymsVal>,
    all_syms: BTreeMap<u64, String>,
}

type SymbolFun =
    Box<dyn for<'a> Fn(&'a mut Counts, &'a mut PerFrameProps) -> Option<&'a mut Metric>>;

struct KSymsVal {
    range_end: u64,
    fun: SymbolFun,
}

#[derive(Default, Clone)]
pub struct Metric {
    pub count: u16,
    pub sub_metrics: BTreeMap<String, Metric>,
}

impl AddAssign for Metric {
    fn add_assign(&mut self, rhs: Self) {
        self.count += rhs.count;
        for (key, value) in rhs.sub_metrics {
            *self.sub_metrics.entry(key).or_default() += value;
        }
    }
}

impl Add for Metric {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut new = self;
        new += rhs;
        new
    }
}

/// Counts instances of symbols in stack traces
#[derive(Default, Clone)]
pub struct Counts {
    pub net_rx_action: Metric,
    pub __napi_poll: Metric,
    /// Catch-all for any function to submit frames to the network stack
    pub netif_receive_skb: Metric,
    pub br_handle_frame: Metric,
    /// netif_receive_skb when called by br_handle_frame
    pub netif_receive_skb_sub_br: Metric,
    pub do_xdp_generic: Metric,
    pub tcf_classify: Metric,
    pub ip_forward: Metric,
    pub ip6_forward: Metric,
    pub ip_local_deliver: Metric,
    pub ip6_input: Metric,
    pub nf_netdev_ingress: Metric,
    pub nf_prerouting_v4: Metric,
    pub nf_prerouting_v6: Metric,
    pub napi_gro_receive_overhead: Metric,
    pub nf_conntrack_in: Metric,
    // pub nf_local_in_v4: u16,
    // pub nf_local_in_v6: u16,
    // pub nf_forward_v4: u16,
    // pub nf_forward_v6: u16
}

struct PerFrameProps {
    in_nf_hook: Metric,
    ip_rcv_finish: Metric,
}

impl KSyms {
    /// Load requested kernel symbols from /proc/kallsyms
    pub fn load() -> io::Result<Self> {
        let mut btree = BTreeMap::new();
        let f = BufReader::new(File::open("/proc/kallsyms")?);

        // Load all the addresses into a BTreeMap
        for line in f.lines() {
            let line = line?;
            let parts = line.split_ascii_whitespace().collect::<Vec<_>>();
            let name = parts[2];
            let addr = u64::from_str_radix(parts[0], 16)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, line.clone()))?;

            btree.insert(addr, name.to_string());
        }

        // Only keep the symbols we're interested in
        let syms = btree
            .iter()
            .filter_map(|(&range_start, name)| {
                match name.as_str() {
                    "net_rx_action" => {
                        Option::<SymbolFun>::Some(Box::new(|cnt, _| Some(&mut cnt.net_rx_action)))
                    }
                    "__napi_poll" => {
                        Option::<SymbolFun>::Some(Box::new(|cnt, _| Some(&mut cnt.__napi_poll)))
                    }
                    "netif_receive_skb"
                    | "netif_receive_skb_core"
                    | "netif_receive_skb_list_internal"
                    | "__netif_receive_skb" => Option::<SymbolFun>::Some(Box::new(
                        |cnt, PerFrameProps { in_nf_hook, .. }| {
                            cnt.nf_netdev_ingress.count =
                                cnt.nf_netdev_ingress.count.max(in_nf_hook.count);
                            Some(&mut cnt.netif_receive_skb)
                        },
                    )),
                    "napi_gro_receive" => Option::<SymbolFun>::Some(Box::new(
                        |cnt, PerFrameProps { in_nf_hook, .. }| {
                            cnt.nf_netdev_ingress.count =
                                cnt.nf_netdev_ingress.count.max(in_nf_hook.count);

                            if cnt.netif_receive_skb.count == 0 {
                                cnt.napi_gro_receive_overhead.count = 1;
                            }

                            Some(&mut cnt.netif_receive_skb)
                        },
                    )),
                    "do_xdp_generic" => {
                        Option::<SymbolFun>::Some(Box::new(|cnt, _| Some(&mut cnt.do_xdp_generic)))
                    }
                    "tcf_classify" => {
                        Option::<SymbolFun>::Some(Box::new(|cnt, _| Some(&mut cnt.tcf_classify)))
                    }
                    "br_handle_frame" => Option::<SymbolFun>::Some(Box::new(
                        |cnt, PerFrameProps { in_nf_hook, .. }| {
                            in_nf_hook.count = 0;
                            cnt.netif_receive_skb_sub_br =
                                std::mem::take(&mut cnt.netif_receive_skb);
                            Some(&mut cnt.br_handle_frame)
                        },
                    )),
                    "ip_forward" => Option::<SymbolFun>::Some(Box::new(
                        |cnt, PerFrameProps { in_nf_hook, .. }| {
                            in_nf_hook.count = 0;
                            Some(&mut cnt.ip_forward)
                        },
                    )),
                    "ip6_forward" => Option::<SymbolFun>::Some(Box::new(
                        |cnt, PerFrameProps { in_nf_hook, .. }| {
                            in_nf_hook.count = 0;
                            Some(&mut cnt.ip6_forward)
                        },
                    )),
                    "ip_local_deliver" => Option::<SymbolFun>::Some(Box::new(
                        |cnt, PerFrameProps { in_nf_hook, .. }| {
                            in_nf_hook.count = 0;
                            Some(&mut cnt.ip_local_deliver)
                        },
                    )),
                    "ip6_input" => Option::<SymbolFun>::Some(Box::new(
                        |cnt, PerFrameProps { in_nf_hook, .. }| {
                            in_nf_hook.count = 0;
                            Some(&mut cnt.ip6_input)
                        },
                    )),
                    "nf_hook_slow" => Option::<SymbolFun>::Some(Box::new(
                        |_, PerFrameProps { in_nf_hook, .. }| Some(in_nf_hook),
                    )),
                    "ip_rcv" => Option::<SymbolFun>::Some(Box::new(
                        |cnt,
                         PerFrameProps {
                             in_nf_hook,
                             ip_rcv_finish,
                             ..
                         }| {
                            if ip_rcv_finish.count == 0 {
                                cnt.nf_prerouting_v4.count =
                                    cnt.nf_prerouting_v4.count.max(in_nf_hook.count);
                            }
                            in_nf_hook.count = 0;
                            None
                        },
                    )),
                    "ip6_rcv" => Option::<SymbolFun>::Some(Box::new(
                        |cnt,
                         PerFrameProps {
                             in_nf_hook,
                             ip_rcv_finish,
                             ..
                         }| {
                            if ip_rcv_finish.count == 0 {
                                cnt.nf_prerouting_v6.count =
                                    cnt.nf_prerouting_v6.count.max(in_nf_hook.count);
                            }
                            in_nf_hook.count = 0;
                            None
                        },
                    )),
                    "ip_rcv_finish" | "ip6_rcv_finish" => Option::<SymbolFun>::Some(Box::new(
                        |_, PerFrameProps { ip_rcv_finish, .. }| Some(ip_rcv_finish),
                    )),
                    "nf_conntrack_in" => {
                        Option::<SymbolFun>::Some(Box::new(|cnt, _| Some(&mut cnt.nf_conntrack_in)))
                    }

                    _ => None,
                }
                .map(|fun| {
                    (
                        range_start,
                        KSymsVal {
                            range_end: btree
                                .range(range_start + 1..)
                                .next()
                                .map(|(&addr, _)| addr)
                                .unwrap_or(range_start + 1),
                            fun,
                        },
                    )
                })
            })
            .collect();

        Ok(Self {
            syms,
            all_syms: btree,
        })
    }
}

impl Counts {
    /// Iterate over the frames in the trace and accumulate the instances of the symbols in this Counts
    #[inline]
    pub unsafe fn acc_trace(
        &mut self,
        ksyms: &KSyms,
        trace_ptr: *const u64,
        max_frames: usize,
        #[cfg(feature = "save-traces")] mut output: impl Write,
    ) {
        let cli = Cli::parse();

        #[cfg(feature = "save-traces")]
        let mut first_iter = true;

        let mut c = Self::default();
        let mut frame_props = PerFrameProps {
            in_nf_hook: Metric::default(),
            ip_rcv_finish: Metric::default(),
        };

        for frame_idx in 0..max_frames {
            // Load stack frame
            let ip = trace_ptr.add(frame_idx).read_volatile();
            if ip == 0 {
                break;
            }

            #[cfg(feature = "save-traces")]
            {
                let _ = write!(output, "{}{ip}", if first_iter { "" } else { "," });
                first_iter = false;
            }

            // Check for known symbols
            if let Some((_, KSymsVal { range_end, fun })) = ksyms.syms.range(..=ip).next_back() {
                // Load sub metric from next_frame_index using all_syms to lookup symbole
                let add_sub_metric =
                    |next_frame_index: usize, parent_metric: &mut Metric| -> Option<String> {
                        let next_ip = trace_ptr.add(next_frame_index).read_volatile();
                        if next_ip == 0 {
                            return None;
                        }

                        let cursor = ksyms.all_syms.lower_bound(Bound::Excluded(&next_ip));

                        if let Some((_, name)) = cursor.peek_prev() {
                            let mut sub_metric = Metric::default();
                            sub_metric.count = 1;
                            parent_metric.sub_metrics.insert(name.clone(), sub_metric);

                            return Some(name.clone());
                        }

                        None
                    };

                if ip < *range_end {
                    if let Some(top_metric) = fun(&mut c, &mut frame_props) {
                        top_metric.count = 1;

                        let mut metric = top_metric;

                        // loop for max_levels times adding sub metrics for each iteration
                        for offset in 1..cli.max_levels {
                            if let Some(name) = add_sub_metric(frame_idx + offset as usize, metric)
                            {
                                metric = metric.sub_metrics.get_mut(&name).unwrap();
                            } else {
                                break;
                            }
                        }
                    }
                }
            }
        }

        #[cfg(feature = "save-traces")]
        let _ = writeln!(output);

        *self += c;
    }
}

impl Add for Counts {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            net_rx_action: self.net_rx_action + rhs.net_rx_action,
            __napi_poll: self.__napi_poll + rhs.__napi_poll,
            netif_receive_skb: self.netif_receive_skb + rhs.netif_receive_skb,
            do_xdp_generic: self.do_xdp_generic + rhs.do_xdp_generic,
            tcf_classify: self.tcf_classify + rhs.tcf_classify,
            br_handle_frame: self.br_handle_frame + rhs.br_handle_frame,
            netif_receive_skb_sub_br: self.netif_receive_skb_sub_br + rhs.netif_receive_skb_sub_br,
            ip_forward: self.ip_forward + rhs.ip_forward,
            ip6_forward: self.ip6_forward + rhs.ip6_forward,
            ip_local_deliver: self.ip_local_deliver + rhs.ip_local_deliver,
            ip6_input: self.ip6_input + rhs.ip6_input,
            nf_netdev_ingress: self.nf_netdev_ingress + rhs.nf_netdev_ingress,
            nf_prerouting_v4: self.nf_prerouting_v4 + rhs.nf_prerouting_v4,
            nf_prerouting_v6: self.nf_prerouting_v6 + rhs.nf_prerouting_v6,
            napi_gro_receive_overhead: self.napi_gro_receive_overhead
                + rhs.napi_gro_receive_overhead,
            nf_conntrack_in: self.nf_conntrack_in + rhs.nf_conntrack_in, // nf_local_in_v4:           self.nf_local_in_v4           + rhs.nf_local_in_v4,
                                                                         // nf_local_in_v6:           self.nf_local_in_v6           + rhs.nf_local_in_v6,
                                                                         // nf_forward_v4:            self.nf_forward_v4            + rhs.nf_forward_v4,
                                                                         // nf_forward_v6:            self.nf_forward_v6            + rhs.nf_forward_v6
        }
    }
}

impl AddAssign for Counts {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.clone() + rhs;
    }
}

impl Sum for Counts {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|acc, e| acc + e).unwrap_or_default()
    }
}
