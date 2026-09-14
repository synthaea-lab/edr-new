//! Uprobe sensor: loads eBPF programs, attaches uprobes to SSL/readline functions,
//! drains ring buffers. Symbol resolution via [`crate::symbol_resolver`].
//!
//! **Status (Phase 4):** Loads and attaches uprobes; drains ring buffers and logs events.
//! Normalization to `schema::Event` deferred to Phase 5 (no event types exist yet).

use std::sync::Arc;

use aya::maps::RingBuf;
use aya::programs::uprobe::UProbeScope;
use aya::programs::UProbe;
use aya::Ebpf;
use log::{info, warn};
use schema::sensor::{Capabilities, EventSink, Sensor, SensorError};
use sensor_linux_wire::{ReadlineInputEvent, TlsCaptureEvent};
use tokio::sync::Notify;

use crate::symbol_resolver::{self, SymbolInfo};

fn err(msg: String) -> SensorError {
    msg.into()
}

/// Loads the embedded eBPF object from the main sensor-linux-ebpf crate.
/// Uprobes share the same eBPF object as tracepoints (built in `sensor-linux-ebpf`).
///
/// # Errors
///
/// Returns [`SensorError`] if the eBPF object fails to load.
#[cfg(ebpf_embedded)]
fn load_ebpf() -> Result<Ebpf, SensorError> {
    // Bump memlock rlimit (needed for older kernels)
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: plain FFI call with a valid pointer to a stack-owned rlimit struct
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        log::debug!("sensor-linux-uprobes: setrlimit(RLIMIT_MEMLOCK) failed: {ret}");
    }

    // Load the eBPF object (built by sensor-linux-ebpf, shared with tracepoints)
    let ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/sensor-linux-ebpf"
    )))
    .map_err(|e| err(format!("failed to load eBPF object: {e}")))?;
    Ok(ebpf)
}

/// This build carries no embedded probes (bpf-linker was absent at build time).
///
/// # Errors
///
/// Always errors — the message says how to provision the toolchain.
#[cfg(not(ebpf_embedded))]
fn load_ebpf() -> Result<Ebpf, SensorError> {
    Err(err(
        "sensor-linux-uprobes was built without embedded eBPF probes (bpf-linker not on PATH \
         at build time) — provision the eBPF toolchain and rebuild"
            .to_string(),
    ))
}

/// Attaches a uprobe to the given function in the target binary.
///
/// # Errors
///
/// Returns [`SensorError`] if the program is not found or attachment fails.
fn attach_uprobe(
    ebpf: &mut Ebpf,
    program_name: &str,
    symbol: &SymbolInfo,
) -> Result<(), SensorError> {
    let program: &mut UProbe = ebpf
        .program_mut(program_name)
        .ok_or_else(|| err(format!("program `{program_name}` not found in eBPF object")))?
        .try_into()
        .map_err(|e| err(format!("`{program_name}` is not a uprobe: {e}")))?;

    program
        .load()
        .map_err(|e| err(format!("kernel verifier rejected `{program_name}`: {e}")))?;

    // Attach uprobe: point = offset, target = library path, scope = all processes
    program
        .attach(symbol.offset, &symbol.library_path, UProbeScope::AllProcesses)
        .map_err(|e| {
            err(format!(
                "failed to attach uprobe `{program_name}` to {}:{} @ 0x{:x}: {e}",
                symbol.library_path.display(),
                symbol.name,
                symbol.offset
            ))
        })?;

    log::info!(
        "sensor-linux-uprobes: attached {program_name} to {}:{} @ 0x{:x}",
        symbol.library_path.display(),
        symbol.name,
        symbol.offset
    );
    Ok(())
}

/// Drains TLS capture events from the ring buffer and logs them.
/// Phase 5 will normalize these to `schema::Event::TlsCapture`.
macro_rules! drain_tls {
    ($guard:expr, $_sink:expr) => {{
        let mut guard = $guard.map_err(|e| err(format!("TLS ring buffer poll failed: {e}")))?;
        let rb = guard.get_inner_mut();
        while let Some(item) = rb.next() {
            if item.len() >= core::mem::size_of::<TlsCaptureEvent>() {
                // SAFETY: item.len() >= size_of::<TlsCaptureEvent>() checked above;
                // TlsCaptureEvent is repr(C) POD; read_unaligned handles arbitrary alignment
                let event = unsafe {
                    core::ptr::read_unaligned(item.as_ptr() as *const TlsCaptureEvent)
                };
                // Phase 5: normalize to schema::Event::TlsCapture
                log::debug!(
                    "sensor-linux-uprobes: TLS capture pid={} direction={} lib_type={} bytes={}",
                    event.meta.pid,
                    event.direction,
                    event.lib_type,
                    event.bytes_len
                );
                // TODO: $sink.on_event(normalize::tls_capture(&event))
            }
        }
        guard.clear_ready();
    }};
}

/// Drains readline events from the ring buffer and logs them.
/// Phase 5 will normalize these to `schema::Event::ReadlineInput`.
macro_rules! drain_readline {
    ($guard:expr, $_sink:expr) => {{
        let mut guard = $guard
            .map_err(|e| err(format!("readline ring buffer poll failed: {e}")))?;
        let rb = guard.get_inner_mut();
        while let Some(item) = rb.next() {
            if item.len() >= core::mem::size_of::<ReadlineInputEvent>() {
                // SAFETY: item.len() >= size_of::<ReadlineInputEvent>() checked above;
                // ReadlineInputEvent is repr(C) POD; read_unaligned handles arbitrary alignment
                let event = unsafe {
                    core::ptr::read_unaligned(item.as_ptr() as *const ReadlineInputEvent)
                };
                // Phase 5: normalize to schema::Event::ReadlineInput
                let input_str =
                    String::from_utf8_lossy(&event.input[..event.input_len as usize]);
                log::debug!(
                    "sensor-linux-uprobes: readline pid={} shell_type={} input=\"{}\"",
                    event.meta.pid,
                    event.shell_type,
                    input_str
                );
                // TODO: $sink.on_event(normalize::readline_input(&event))
            }
        }
        guard.clear_ready();
    }};
}

/// Uprobe sensor. `run` blocks until Ctrl-C or [`Sensor::stop`].
pub struct UprobesSensor {
    stop: Arc<Notify>,
}

impl Default for UprobesSensor {
    fn default() -> Self {
        Self::new()
    }
}

impl UprobesSensor {
    #[must_use]
    pub fn new() -> Self {
        Self {
            stop: Arc::new(Notify::new()),
        }
    }

    async fn run_async(&mut self, _sink: Box<dyn EventSink>) -> Result<(), SensorError> {
        let mut ebpf = load_ebpf()?;

        // Initialize eBPF logger
        match aya_log::EbpfLogger::init(&mut ebpf) {
            Err(e) => {
                warn!("sensor-linux-uprobes: failed to initialize eBPF logger: {e}");
            }
            Ok(logger) => {
                let mut logger =
                    tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)
                        .map_err(|e| err(format!("eBPF logger fd: {e}")))?;
                tokio::task::spawn(async move {
                    loop {
                        let mut guard = logger.readable_mut().await.unwrap();
                        guard.get_inner_mut().flush();
                        guard.clear_ready();
                    }
                });
            }
        }

        // Resolve and attach TLS uprobes
        info!("sensor-linux-uprobes: resolving TLS symbols...");
        let tls_symbols = symbol_resolver::resolve_tls_symbols()
            .map_err(|e| err(format!("TLS symbol resolution failed: {e}")))?;

        for symbol in &tls_symbols {
            // Attach ssl_write to SSL_write/SSL_write_ex
            if (symbol.name == "SSL_write" || symbol.name == "SSL_write_ex")
                && let Err(e) = attach_uprobe(&mut ebpf, "ssl_write", symbol)
            {
                warn!("sensor-linux-uprobes: failed to attach ssl_write: {e}");
            }
            // Attach ssl_read_entry to SSL_read/SSL_read_ex
            if (symbol.name == "SSL_read" || symbol.name == "SSL_read_ex")
                && let Err(e) = attach_uprobe(&mut ebpf, "ssl_read_entry", symbol)
            {
                warn!("sensor-linux-uprobes: failed to attach ssl_read_entry: {e}");
            }
            // Also attach the uretprobe (ssl_read_exit)
            if (symbol.name == "SSL_read" || symbol.name == "SSL_read_ex")
                && let Err(e) = attach_uprobe(&mut ebpf, "ssl_read_exit", symbol)
            {
                warn!("sensor-linux-uprobes: failed to attach ssl_read_exit: {e}");
            }
        }

        // Resolve and attach readline uprobes
        info!("sensor-linux-uprobes: resolving readline symbols...");
        let readline_symbols = symbol_resolver::resolve_readline_symbols()
            .map_err(|e| err(format!("readline symbol resolution failed: {e}")))?;

        for symbol in &readline_symbols {
            if symbol.name == "readline"
                && let Err(e) = attach_uprobe(&mut ebpf, "readline_exit", symbol)
            {
                warn!("sensor-linux-uprobes: failed to attach readline_exit: {e}");
            }
        }

        // Open ring buffers
        let mut ring = |map: &str| -> Result<_, SensorError> {
            let m = ebpf
                .take_map(map)
                .ok_or_else(|| err(format!("map {map} not found in eBPF object")))?;
            let rb = RingBuf::try_from(m)
                .map_err(|e| err(format!("map {map} is not a ring buffer: {e}")))?;
            tokio::io::unix::AsyncFd::with_interest(rb, tokio::io::Interest::READABLE)
                .map_err(|e| err(format!("ring buffer fd for {map}: {e}")))
        };

        let mut tls_ring_buf = ring("TLS_CAPTURE_EVENTS")?;
        let mut readline_ring_buf = ring("READLINE_EVENTS")?;

        info!("sensor-linux-uprobes: listening for TLS/readline events");

        let ctrl_c = tokio::signal::ctrl_c();
        tokio::pin!(ctrl_c);
        loop {
            tokio::select! {
                _ = &mut ctrl_c => break,
                _ = self.stop.notified() => break,
                guard = tls_ring_buf.readable_mut() => {
                    drain_tls!(guard, _sink);
                }
                guard = readline_ring_buf.readable_mut() => {
                    drain_readline!(guard, _sink);
                }
            }
        }

        info!("sensor-linux-uprobes: exiting");
        Ok(())
    }
}

impl Sensor for UprobesSensor {
    fn name(&self) -> &str {
        "linux-uprobes"
    }

    fn capabilities(&self) -> Capabilities {
        // Phase 5: report actual capabilities when normalization is implemented
        Capabilities {
            exec_events: false,
            file_events: false,
            connect_events: false,
            user_attribution: true,  // EventMeta includes uid/gid
            parent_lineage: true,    // EventMeta includes ppid/parent_comm
        }
    }

    fn run(&mut self, sink: Box<dyn EventSink>) -> Result<(), SensorError> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| err(format!("failed to create tokio runtime: {e}")))?
            .block_on(self.run_async(sink))
    }

    fn stop(&mut self) {
        self.stop.notify_one();
    }
}
