pub mod file_logger;
pub mod metrics_collector;
pub mod prometheus_logger;
pub mod trace_analyzer;
pub mod websocket_client;

use self::websocket_client::WebsocketClient;
use actix::{Addr, Message};

/// Signal new client connected to the `MetricsCollector` actor
#[derive(Message)]
#[rtype(result = "()")]
struct ClientConnected {
    addr: Addr<WebsocketClient>,
}

/// Signal client disconnected to the `MetricsCollector` actor
#[derive(Message)]
#[rtype(result = "()")]
struct ClientDisconnected {
    addr: Addr<WebsocketClient>,
}

/// Represents an update for a single metric on a single CPU
/// from the `TraceAnalyzer` actor.
#[derive(Message)]
#[rtype(result = "()")]
struct MetricUpdate {
    /// Whether to clear the metrics root or not
    clear: bool,

    /// This is the hierarchical name of the metric.
    /// For example, "RX softirq/Bridging".
    name: String,

    /// CPU index this metric update is for
    cpuid: usize,

    /// Fraction of CPU time in the [0, 1] range
    cpu_frac: f64,
}

/// Used to trigger the `MetricsCollector` to submit the update
/// to all the clients.
#[derive(Message, Clone)]
#[rtype(result = "()")]
struct SubmitUpdate {
    /// Power drawn by the CPU in the networking stack
    /// as measured.
    /// It's None if the RAPL interface isn't available.
    net_power_w: Option<f64>,

    /// Fraction of the CPU time spent by the user-space tool
    user_space_overhead: f64,

    /// Metrics acquired from /proc/stat for validation
    procfs_metrics: Vec<f64>,
}

/// Wrapper around a MessagePack buffer to send to websocket clients.
/// This struct exists solely because Vec<u8> can't implement Message.
#[derive(Message)]
#[rtype(result = "()")]
struct EncodedUpdate {
    inner: Vec<u8>,
}
