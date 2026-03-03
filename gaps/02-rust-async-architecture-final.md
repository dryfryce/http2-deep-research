# Rust Async Architecture for High-Performance HTTP/2 Stress Testing Framework

## Overview
This document outlines the optimal async patterns and architecture for building Phoenix, a Rust HTTP/2 stress testing framework capable of handling 100k+ concurrent connections. The focus is on extreme concurrency, connection pooling, rate limiting, and performance optimization.

## Architecture Diagram

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

## 1. Tokio Architecture for Massive Concurrency

### Task Management for 100k+ Connections

```rust
// Optimal pattern for massive concurrency
use futures::stream::{FuturesUnordered, StreamExt};
use tokio::sync::Semaphore;

struct ConnectionManager {
    max_concurrent: usize,
    semaphore: Arc<Semaphore>,
    task_set: FuturesUnordered<tokio::task::JoinHandle<()>>,
}

impl ConnectionManager {
    async fn spawn_connections(&mut self, target: &str, count: usize) {
        for i in 0..count {
            let permit = self.semaphore.clone().acquire_owned().await.unwrap();
            let target = target.to_string();
            
            let handle = tokio::spawn(async move {
                // Connection logic here
                let _stream = connect_to_target(&target).await;
                drop(permit); // Release semaphore permit
            });
            
            self.task_set.push(handle);
            
            // Clean completed tasks periodically
            if i % 1000 == 0 {
                self.clean_completed_tasks().await;
            }
        }
    }
    
    async fn clean_completed_tasks(&mut self) {
        while let Some(result) = self.task_set.next().await {
            if let Err(e) = result {
                eprintln!("Task failed: {:?}", e);
            }
        }
    }
}
```

### Worker Pool with Work Stealing

```rust
use tokio::task::yield_now;
use std::sync::atomic::{AtomicUsize, Ordering};

struct WorkStealingPool {
    workers: Vec<tokio::task::JoinHandle<()>>,
    work_queue: Arc<tokio::sync::Mutex<VecDeque<WorkItem>>>,
    steal_counter: Arc<AtomicUsize>,
}

impl WorkStealingPool {
    async fn new(num_workers: usize) -> Self {
        let work_queue = Arc::new(tokio::sync::Mutex::new(VecDeque::new()));
        let steal_counter = Arc::new(AtomicUsize::new(0));
        let mut workers = Vec::with_capacity(num_workers);
        
        for worker_id in 0..num_workers {
            let queue = work_queue.clone();
            let counter = steal_counter.clone();
            
            let worker = tokio::spawn(async move {
                loop {
                    // Try to get work from local queue
                    let work = {
                        let mut q = queue.lock().await;
                        q.pop_front()
                    };
                    
                    match work {
                        Some(work) => {
                            process_work(worker_id, work).await;
                        }
                        None => {
                            // Work stealing: try other queues
                            counter.fetch_add(1, Ordering::Relaxed);
                            yield_now().await;
                        }
                    }
                }
            });
            
            workers.push(worker);
        }
        
        Self { workers, work_queue, steal_counter }
    }
}
```

## 2. HTTP/2 Connection Pool Design

### Intelligent Connection Pool

```rust
use hyper::client::HttpConnector;
use hyper_rustls::HttpsConnector;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Notify};

struct SmartConnectionPool {
    connections: Arc<Mutex<Vec<PooledConnection>>>,
    max_pool_size: usize,
    min_pool_size: usize,
    idle_timeout: Duration,
    health_checker: tokio::task::JoinHandle<()>,
    new_connection_notify: Arc<Notify>,
}

impl SmartConnectionPool {
    async fn borrow(&self) -> Result<PooledConnection, PoolError> {
        loop {
            let mut connections = self.connections.lock().await;
            
            // Find healthy connection
            for i in 0..connections.len() {
                if connections[i].is_healthy() && !connections[i].is_in_use() {
                    let mut conn = connections.remove(i);
                    conn.mark_in_use();
                    return Ok(conn);
                }
            }
            
            // Create new connection if under max size
            if connections.len() < self.max_pool_size {
                drop(connections);
                let new_conn = self.create_connection().await?;
                new_conn.mark_in_use();
                return Ok(new_conn);
            }
            
            // Wait for connection to become available
            drop(connections);
            self.new_connection_notify.notified().await;
        }
    }
    
    async fn create_connection(&self) -> Result<PooledConnection, PoolError> {
        // HTTP/2 specific connection setup
        let https = HttpsConnector::with_native_roots();
        let client = hyper::Client::builder()
            .http2_only(true)  // Force HTTP/2
            .build(https);
            
        Ok(PooledConnection {
            client,
            last_used: Instant::now(),
            in_use: false,
            stream_count: 0,
            max_streams: 100,  // HTTP/2 default
        })
    }
}
```

### HTTP/2 Multiplexing Optimization

```rust
struct H2Multiplexer {
    connection: PooledConnection,
    pending_requests: HashMap<StreamId, PendingRequest>,
    max_concurrent_streams: usize,
    available_streams: Semaphore,
}

impl H2Multiplexer {
    async fn send_request(&self, request: Request) -> Result<Response, H2Error> {
        // Acquire stream slot
        let _permit = self.available_streams.acquire().await?;
        
        // Send request on existing HTTP/2 connection
        let response = self.connection.client.request(request).await?;
        
        Ok(response)
    }
    
    fn calculate_optimal_connections(&self, target_rps: u32, avg_latency: Duration) -> usize {
        // Based on Little's Law: L = λW
        // Where L = concurrent requests, λ = arrival rate, W = latency
        let concurrent_needed = (target_rps as f64 * avg_latency.as_secs_f64()).ceil() as usize;
        
        // Account for HTTP/2 stream limits
        let connections_needed = (concurrent_needed as f64 / self.max_concurrent_streams as f64).ceil() as usize;
        
        // Add 20% buffer
        (connections_needed as f64 * 1.2).ceil() as usize
    }
}
```

## 3. Rate Limiting with Coordinated Omission Awareness

### Production-Grade Rate Limiter

```rust
use governor::{Quota, RateLimiter};
use std::sync::Arc;
use tokio::time::{Instant, Duration};

struct PhoenixRateLimiter {
    limiter: Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
    target_rps: u32,
    omission_stats: OmissionStats,
    adjustment_interval: Duration,
}

impl PhoenixRateLimiter {
    async fn maintain_rate(&self, mut requests: usize) {
        let batch_size = self.calculate_optimal_batch_size();
        let mut last_send = Instant::now();
        
        while requests > 0 {
            let batch = std::cmp::min(requests, batch_size);
            
            // Check for coordinated omission
            let now = Instant::now();
            let expected_next = last_send + Duration::from_nanos(1_000_000_000 / self.target_rps as u64);
            
            if now > expected_next {
                self.omission_stats.record_omission(now.duration_since(expected_next));
            }
            
            // Acquire permits for batch
            for _ in 0..batch {
                self.limiter.until_ready().await;
            }
            
            // Send batch
            self.send_batch(batch).await;
            last_send = Instant::now();
            requests -= batch;
        }
    }
    
    fn calculate_optimal_batch_size(&self) -> usize {
        // Dynamic batch sizing based on network conditions
        let latency_percentile = self.omission_stats.latency_percentile(0.95);
        
        match latency_percentile.as_millis() {
            0..=10 => 100,    // Low latency: small batches
            11..=50 => 50,    // Medium latency: medium batches  
            51..=100 => 20,   // High latency: small batches
            _ => 10,          // Very high latency: tiny batches
        }
    }
}
```

### Latency Histogram for Accurate Metrics

```rust
use hdrhistogram::Histogram;

struct LatencyTracker {
    histogram: Mutex<Histogram<u64>>,
    percentiles: Vec<f64>,
}

impl LatencyTracker {
    fn record_latency(&self, latency: Duration) {
        let mut hist = self.histogram.lock().unwrap();
        hist.record(latency.as_micros() as u64).unwrap();
    }
    
    fn get_percentiles(&self) -> HashMap<f64, Duration> {
        let hist = self.histogram.lock().unwrap();
        self.percentiles.iter()
            .map(|&p| (p, Duration::from_micros(hist.value_at_percentile(p) as u64)))
            .collect()
    }
    
    fn coordinated_omission_score(&self) -> f64 {
        // Calculate how much latency variance indicates coordinated omission
        let hist = self.histogram.lock().unwrap();
        let p50 = hist.value_at_percentile(50.0);
        let p99 = hist.value_at_percentile(99.0);
        
        if p50 > 0 {
            (p99 as f64 / p50 as f64) - 1.0
        } else {
            0.0
        }
    }
}
```

## 4. Backpressure and Flow Control

### HTTP/2-Specific Backpressure

```rust
struct H2BackpressureManager {
    connection_window: Arc<AtomicU32>,
    stream_windows: HashMap<StreamId, Arc<AtomicU32>>,
    max_window_size: u32,
    window_update_threshold: u32,
}

impl H2BackpressureManager {
    async fn wait_for_window(&self, stream_id: StreamId, needed: u32) {
        loop {
            let window = self.get_stream_window(stream_id);
            if window >= needed {
                break;
            }
            
            // Wait for window update
            tokio::time::sleep(Duration::from_micros(100)).await;
        }
    }
    
    fn adaptive_window_size(&self, rtt: Duration, bandwidth: f64) -> u32 {
        // BDP = Bandwidth * RTT
        let bdp_bytes = (bandwidth * rtt.as_secs_f64()) as u32;
        
        // TCP-style window scaling: 2 * BDP for HTTP/2
        std::cmp::min(bdp_bytes * 2, self.max_window_size)
    }
}
```

## 5. Attack Module System

### Extensible Plugin Architecture

```rust
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::any::Any;

#[async_trait]
pub trait AttackModule: Send + Sync {
    async fn execute(&self, ctx: &AttackContext) -> Result<AttackResult, AttackError>;
    fn name(&self) -> &'static str;
    fn config_schema(&self) -> serde_json::Value;
    fn as_any(&self) -> &dyn Any;
}

struct ModuleRegistry {
    modules: HashMap<String, Box<dyn AttackModule>>,
    loader: ModuleLoader,
}

impl ModuleRegistry {
    fn load_dynamic(&mut self, path: &str) -> Result<(), LoadError> {
        // Load shared library
        let lib = unsafe { libloading::Library::new(path)? };
        
        // Get module constructor
        let constructor: libloading::Symbol<fn() -> Box<dyn AttackModule>> =
            unsafe { lib.get(b"create_module")? };
            
        let module = constructor();
        self.modules.insert(module.name().to_string(), module);
        
        Ok(())
    }
    
    fn get_module(&self, name: &str) -> Option<&dyn AttackModule> {
        self.modules.get(name).map(|m| m.as_ref())
    }
}
```

## 6. Socket and Network Optimization

### Advanced Socket Configuration

```rust
use socket2::{Socket, Domain, Type, Protocol, TcpKeepalive};
use std::os::fd::AsRawFd;

fn create_high_performance_socket() -> Result<Socket, std::io::Error> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    
    // TCP optimizations
    socket.set_nodelay(true)?;
    socket.set_reuse_address(true)?;
    
    #[cfg(target_os = "linux")]
    {
        // Linux-specific optimizations
        socket.set_reuse_port(true)?;
        
        // Enable TCP fast open
        let fastopen: libc::c_int = 1;
        unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_FASTOPEN,
                &fastopen as *const _ as *const libc::c_void,
                std::mem::size_of_val(&fastopen) as libc::socklen_t,
            );
        }
        
        // Increase buffer sizes
        socket.set_send_buffer_size(4 * 1024 * 1024)?;  // 4MB
        socket.set_recv_buffer_size(4 * 1024 * 1024)?;  // 4MB
    }
    
    // TCP keepalive
    let keepalive = TcpKeepalive::new()
        .with_time(Duration::from_secs(30))
        .with_interval(Duration::from_secs(10))
        .with_retries(3);
    socket.set_tcp_keepalive(&keepalive)?;
    
    Ok(socket)
}
```

### Port Exhaustion Mitigation

```rust
struct PortManager {
    base_port: u16,
    port_range: u16,
    next