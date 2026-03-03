# Rust Async Architecture for High-Performance HTTP/2 Stress Testing Framework

## Complete Architecture Guide

### System Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Phoenix Framework                         │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   CLI Layer │  │ Config Layer│  │  Plugin     │         │
│  │  (clap)     │◄─┤  (serde)    │◄─┤  Registry   │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
│           │               │               │                 │
│           ▼               ▼               ▼                 │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              Attack Orchestrator                    │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │   │
│  │  │ Rate        │  │ Connection  │  │  Worker     │ │   │
│  │  │ Controller  │  │   Pool      │  │   Pool      │ │   │
│  │  │ (governor)  │  │ (hyper/h2)  │  │ (tokio)     │ │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘ │   │
│  └─────────────────────────────────────────────────────┘   │
│                     │         │         │                  │
│                     ▼         ▼         ▼                  │
│          ┌─────────────┬─────────────┬─────────────┐      │
│          │ HTTP/2      │   Slowloris │ Resource    │      │
│          │ Rapid Reset │   Attack    │ Exhaustion  │      │
│          │ Attack      │             │ Attack      │      │
│          └─────────────┴─────────────┴─────────────┘      │
│                     │         │         │                  │
│                     ▼         ▼         ▼                  │
│          ┌─────────────────────────────────────────┐      │
│          │          Network Layer                  │      │
│          │  ┌─────────────────────────────────┐    │      │
│          │  │    Socket Optimization          │    │      │
│          │  │  • TCP_NODELAY                 │    │      │
│          │  │  • SO_REUSEPORT                │    │      │
│          │  │  • Buffer tuning               │    │      │
│          │  └─────────────────────────────────┘    │      │
│          │  ┌─────────────────────────────────┐    │      │
│          │  │    TLS Configuration            │    │      │
│          │  │  • HTTP/2 ALPN                 │    │      │
│          │  │  • Session resumption          │    │      │
│          │  │  • Cipher suite optimization   │    │      │
│          │  └─────────────────────────────────┘    │      │
│          └─────────────────────────────────────────┘      │
│                     │                                      │
│                     ▼                                      │
│          ┌─────────────────────────────────────────┐      │
│          │          Metrics & Reporting            │      │
│          │  • Request latency histogram           │      │
│          │  • Error rate tracking                 │      │
│          │  • Throughput monitoring               │      │
│          │  • Coordinated omission detection      │      │
│          └─────────────────────────────────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

## 1. Massive Concurrency Patterns

### Task-per-Connection vs Connection Pool

**Task-per-Connection Pattern:**
```rust
async fn handle_connections_task_per_connection(listener: TcpListener) {
    let mut tasks = FuturesUnordered::new();
    
    while let Ok((stream, _)) = listener.accept().await {
        tasks.push(tokio::spawn(async move {
            handle_connection(stream).await;
        }));
        
        // Limit concurrent tasks
        if tasks.len() > 100_000 {
            while tasks.len() > 50_000 {
                let _ = tasks.next().await;
            }
        }
    }
}
```

**Connection Pool Pattern (Recommended):**
```rust
struct ConnectionPool {
    connections: Arc<Mutex<VecDeque<PooledConnection>>>,
    semaphore: Arc<Semaphore>,
    factory: ConnectionFactory,
}

impl ConnectionPool {
    async fn execute_request(&self, request: Request) -> Result<Response, PoolError> {
        let permit = self.semaphore.acquire().await?;
        let mut conn = self.borrow_connection().await?;
        
        let result = conn.execute(request).await;
        
        self.return_connection(conn).await;
        drop(permit);
        
        result
    }
}
```

### Performance Comparison

| Pattern | Memory Usage | Context Switches | Connection Setup | Best For |
|---------|-------------|------------------|------------------|----------|
| Task-per-Connection | High (~2KB/task) | High | Per request | Short-lived connections |
| Connection Pool | Low (shared) | Low | Once per pool | Long-lived, high RPS |
| Hybrid Approach | Medium | Medium | Balanced | Mixed workloads |

## 2. HTTP/2 Connection Management

### HTTP/2-Specific Optimizations

```rust
use hyper::client::HttpConnector;
use hyper_rustls::HttpsConnector;
use h2::client;

struct H2Connection {
    inner: client::Connection<TcpStream>,
    max_concurrent_streams: usize,
    available_streams: Semaphore,
    ping_interval: Duration,
}

impl H2Connection {
    async fn new(addr: SocketAddr) -> Result<Self, H2Error> {
        let tcp = TcpStream::connect(addr).await?;
        let (client, h2) = client::handshake(tcp).await?;
        
        // Spawn connection driver
        tokio::spawn(async move {
            if let Err(e) = h2.await {
                eprintln!("H2 connection error: {:?}", e);
            }
        });
        
        Ok(Self {
            inner: client,
            max_concurrent_streams: 100,
            available_streams: Semaphore::new(100),
            ping_interval: Duration::from_secs(30),
        })
    }
    
    async fn send_request(&self, request: Request<()>) -> Result<Response, H2Error> {
        let permit = self.available_streams.acquire().await?;
        
        let (response, _) = self.inner.send_request(request, false)?;
        let response = response.await?;
        
        drop(permit);
        Ok(response)
    }
}
```

### Connection Pool with HTTP/2 Multiplexing

```rust
struct H2ConnectionPool {
    connections: Vec<Arc<H2Connection>>,
    round_robin: AtomicUsize,
    health_checker: HealthChecker,
}

impl H2ConnectionPool {
    fn optimal_pool_size(&self, target_rps: u32, avg_latency_ms: u64) -> usize {
        // Little's Law: L = λW
        let concurrent_streams_needed = (target_rps as f64 * avg_latency_ms as f64 / 1000.0).ceil() as usize;
        
        // Account for HTTP/2 stream limits (default 100 streams per connection)
        let connections_needed = (concurrent_streams_needed as f64 / 100.0).ceil() as usize;
        
        // Add 25% buffer for headroom
        (connections_needed as f64 * 1.25).ceil() as usize
    }
    
    async fn get_connection(&self) -> Arc<H2Connection> {
        let idx = self.round_robin.fetch_add(1, Ordering::Relaxed) % self.connections.len();
        self.connections[idx].clone()
    }
}
```

## 3. Rate Limiting Architecture

### Coordinated Omission-Aware Rate Limiter

```rust
use std::time::{Instant, Duration};
use tokio::sync::Mutex;

struct CoordinatedOmissionAwareLimiter {
    target_interval: Duration,
    last_scheduled: Mutex<Instant>,
    omission_stats: Arc<OmissionStats>,
    histogram: Arc<Histogram<u64>>,
}

impl CoordinatedOmissionAwareLimiter {
    async fn next_send_time(&self) -> Instant {
        let mut last = self.last_scheduled.lock().await;
        let now = Instant::now();
        
        // Calculate when next request should have been sent
        let next_theoretical = *last + self.target_interval;
        
        if now >= next_theoretical {
            // We're behind - record coordinated omission
            let delay = now.duration_since(next_theoretical);
            self.omission_stats.record(delay);
            
            // Schedule immediately
            *last = now;
            now
        } else {
            // Schedule at theoretical time
            *last = next_theoretical;
            next_theoretical
        }
    }
    
    fn omission_score(&self) -> f64 {
        // Calculate percentage of requests affected by coordinated omission
        let stats = self.omission_stats.snapshot();
        if stats.total_requests > 0 {
            stats.omitted_requests as f64 / stats.total_requests as f64
        } else {
            0.0
        }
    }
}
```

### Adaptive Rate Control

```rust
struct AdaptiveRateController {
    target_rps: u32,
    current_rps: AtomicU32,
    error_rate: f64,
    latency_percentile: Duration,
    adjustment_strategy: AdjustmentStrategy,
}

impl AdaptiveRateController {
    fn adjust_rate(&self, metrics: &AttackMetrics) -> u32 {
        let current_error_rate = metrics.error_rate();
        let current_latency = metrics.p95_latency();
        
        match self.adjustment_strategy {
            AdjustmentStrategy::Conservative => {
                if current_error_rate > 0.05 || current_latency > Duration::from_secs(1) {
                    // Reduce rate by 20%
                    (self.current_rps.load(Ordering::Relaxed) as f64 * 0.8) as u32
                } else if current_error_rate < 0.01 && current_latency < Duration::from_millis(100) {
                    // Increase rate by 10%
                    (self.current_rps.load(Ordering::Relaxed) as f64 * 1.1) as u32
                } else {
                    self.current_rps.load(Ordering::Relaxed)
                }
            }
            AdjustmentStrategy::Aggressive => {
                // More aggressive adjustments
                // ...
            }
        }
    }
}
```

## 4. Backpressure and Flow Control

### HTTP/2 Window Management

```rust
struct H2FlowController {
    connection_window: Arc<AtomicU32>,
    stream_windows: DashMap<StreamId, Arc<AtomicU32>>,
    window_update_receiver: mpsc::Receiver<WindowUpdate>,
}

impl H2FlowController {
    async fn wait_for_window(&self, stream_id: StreamId, needed: u32) {
        loop {
            if let Some(window) = self.stream_windows.get(&stream_id) {
                if window.load(Ordering::Acquire) >= needed {
                    break;
                }
            }
            
            // Wait for window update or timeout
            tokio::select! {
                update = self.window_update_receiver.recv() => {
                    if let Some(update) = update {
                        self.handle_window_update(update).await;
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(10)) => {
                    // Timeout, check again
                }
            }
        }
    }
    
    fn calculate_optimal_window(&self, bandwidth_bps: f64, rtt: Duration) -> u32 {
        // Bandwidth-Delay Product (BDP)
        let bdp_bytes = (bandwidth_bps * rtt.as_secs_f64() / 8.0) as u32;
        
        // For HTTP/2, use 2-3x BDP for better performance
        std::cmp::min(bdp_bytes * 3, 16 * 1024 * 1024) // Max 16MB
    }
}
```

## 5. Error Handling and Resilience

### Comprehensive Error Hierarchy

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PhoenixError {
    #[error("Network error: {0}")]
    Network(#[from] std::io::Error),
    
    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),
    
    #[error("HTTP/2 protocol error: {0}")]
    Http2(#[from] h2::Error),
    
    #[error("Timeout after {0:?}")]
    Timeout(Duration),
    
    #[error("Rate limit exceeded: {0}/sec")]
    RateLimit(u32),
    
    #[error("Connection pool exhausted")]
    PoolExhausted,
    
    #[error("Configuration error: {0}")]
    Config(String),
    
    #[error("Attack module error: {0}")]
    AttackModule(Box<dyn std::error::Error + Send + Sync>),
}

impl PhoenixError {
    pub fn should_retry(&self) -> bool {
        matches!(self, 
            PhoenixError::Network(_) |
            PhoenixError::Timeout(_) |
            PhoenixError::Http2(_)  // Some HTTP/2 errors are retryable
        )
    }
    
    pub fn is_fatal(&self) -> bool {
        matches!(self,
            PhoenixError::Config(_) |
            PhoenixError::RateLimit(_)  // Don't retry rate limits immediately
        )
    }
}
```

### Retry Logic with Exponential Backoff

```rust
struct RetryPolicy {
    max_retries: usize,
    base_delay: Duration,
    max_delay: Duration,
    jitter: bool,
}

impl RetryPolicy {
    async fn execute_with_retry<F, T, E>(&self, mut operation: F) -> Result<T, E>
    where
        F: FnMut() -> Result<T, E>,
        E: std::error::Error + Send + Sync + 'static,
    {
        let mut attempt = 0;
        let mut delay = self.base_delay;
        
        loop {
            match operation() {
                Ok(result) => return Ok(result),
                Err(e) if attempt >= self.max_retries => return Err(e),
                Err(e) => {
                    attempt += 1;
                    
                    // Add jitter if enabled
                    let actual_delay = if self.jitter {
                        let jitter = rand::random::<f64>() * 0.1; // ±10% jitter
                        delay.mul_f64(1.0 + jitter - 0.05)
                    } else {
                        delay
                    };
                    
                    tokio::time::sleep(actual_delay).await;
                    
                    // Exponential backoff
                    delay = std::cmp::min(delay * 2, self.max_delay);
                }
            }
        }
    }
}
```

## 6. Performance Profiling

### Benchmarking Setup

```rust
use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use std::time::Duration;

fn benchmark_connection_pool(c: &mut Criterion) {
    let mut group = c.benchmark_group("connection_pool");
    
    group.sample_size(1000);
    group.measurement_time(Duration::from_secs(30));
    group.warm_up_time(Duration::from_secs(5));
    
    for size in [10, 100, 1000, 10000].iter() {
        group.bench_with_input(
            BenchmarkId::new("borrow_return", size),
            size,
            |b, &size| {
                b.to_async(tokio::runtime::Runtime::new().unwrap())
                    .iter(|| async {
                        let pool = ConnectionPool::new(size).await;
                        let conn = pool.borrow().await.unwrap();
                        pool.return_connection(conn).await;
                    });
            },
        );
    }
    
    group.finish();
}

criterion_group!(benches, benchmark_connection_pool);
criterion_main!(benches);
```

### Memory Profiling

```bash
# Install profiling tools
cargo install flamegraph heaptrack

# Generate CPU flamegraph
cargo flamegraph --bin phoenix -- --target https://example.com --rps 10000

# Generate memory profile
heaptrack phoenix -- --target https://example.com --rps 10000

# Analyze with perf
perf record -g --call-graph dwarf ./target/release/phoenix
perf report
```

## 7. Configuration System

### TOML Configuration Example

```toml
# phoenix.toml
[global]
name = "http2-stress-test"
duration = "5m"
report_interval = "10s"
output_dir = "./results"

[rate_limiting]
target_rps = 10000
burst_multiplier = 1.5
adaptive = true

[connection_pool]
max_size = 1000
min_size = 100
idle_timeout = "30s"
health_check_interval = "10s"

[[attacks]]
name = "rapid-reset"
module = "rapid_reset"
enabled = true

[attacks.config]
max_streams = 10000
reset_interval_ms = 1
target_path = "/api/v1/data"

[[attacks]]
name = "slowloris"
module = "slowloris"
enabled = false

[attacks.config]
connections = 5000
send_interval_ms = 30000
headers = [
    "X-Custom: Value",
    "User-A