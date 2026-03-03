# Rust Async Architecture for High-Performance HTTP/2 Stress Testing Framework

## Overview
This document outlines the optimal async patterns and architecture for building Phoenix, a Rust HTTP/2 stress testing framework capable of handling 100k+ concurrent connections. The focus is on extreme concurrency, connection pooling, rate limiting, and performance optimization.

## 1. Tokio Architecture for Massive Concurrency

### Task Management Strategies

#### JoinSet vs FuturesUnordered
For managing 100k+ concurrent tasks, the choice between `tokio::task::JoinSet` and `futures::stream::FuturesUnordered` is critical:

```rust
// Using JoinSet for structured task management
use tokio::task::JoinSet;

async fn manage_tasks_with_joinset() -> Result<(), Box<dyn std::error::Error>> {
    let mut set = JoinSet::new();
    
    for i in 0..100_000 {
        set.spawn(async move {
            // Task logic here
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
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

// Using FuturesUnordered for unordered completion
use futures::stream::{FuturesUnordered, StreamExt};

async fn manage_tasks_with_futures_unordered() {
    let mut futures = FuturesUnordered::new();
    
    for i in 0..100_000 {
        futures.push(async move {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            i
        });
    }
    
    while let Some(result) = futures.next().await {
        println!("Task completed: {}", result);
    }
}
```

**Comparison:**
- **JoinSet**: Better for structured task management, automatic cancellation, and error propagation
- **FuturesUnordered**: More lightweight, better for fire-and-forget tasks, lower overhead
- **Recommendation**: Use `FuturesUnordered` for connection handling where order doesn't matter

### Worker Pool Patterns

#### Task-per-connection vs Shared Pools
```rust
// Worker pool with channel-based task distribution
use tokio::sync::mpsc;
use std::sync::Arc;

struct WorkerPool {
    workers: Vec<tokio::task::JoinHandle<()>>,
    sender: mpsc::Sender<Task>,
}

impl WorkerPool {
    async fn new(num_workers: usize) -> Self {
        let (sender, mut receiver) = mpsc::channel::<Task>(1000);
        let mut workers = Vec::with_capacity(num_workers);
        
        for worker_id in 0..num_workers {
            let receiver = receiver.clone();
            let worker = tokio::spawn(async move {
                while let Some(task) = receiver.recv().await {
                    // Process task
                    process_task(worker_id, task).await;
                }
            });
            workers.push(worker);
        }
        
        Self { workers, sender }
    }
    
    async fn submit(&self, task: Task) {
        self.sender.send(task).await.unwrap();
    }
}

// Task-per-connection approach (simpler but higher overhead)
async fn handle_connection_per_task(stream: TcpStream) {
    tokio::spawn(async move {
        // Handle connection
        process_connection(stream).await;
    });
}
```

### Pinning Tasks to Specific Threads
```rust
use tokio::runtime::Builder;
use std::thread;

// Custom runtime with thread affinity
fn create_affinity_runtime() -> tokio::runtime::Runtime {
    Builder::new_multi_thread()
        .worker_threads(4)
        .on_thread_start(|| {
            // Set thread affinity or priority
            thread::current().set_name("phoenix-worker");
        })
        .enable_all()
        .build()
        .unwrap()
}

// Using tokio::task::spawn_blocking for CPU-intensive work
async fn cpu_intensive_work() {
    let result = tokio::task::spawn_blocking(|| {
        // CPU-intensive computation
        compute_heavy_stuff()
    }).await.unwrap();
}
```

## 2. Connection Pool Design

### HTTP/2 Connection Management

```rust
use hyper::client::HttpConnector;
use hyper_rustls::HttpsConnector;
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

struct ConnectionPool {
    connections: Arc<Mutex<VecDeque<PooledConnection>>>,
    max_size: usize,
    semaphore: Arc<Semaphore>,
    health_check_interval: Duration,
}

struct PooledConnection {
    client: hyper::Client<HttpsConnector<HttpConnector>>,
    last_used: Instant,
    is_healthy: bool,
}

impl ConnectionPool {
    async fn new(max_size: usize) -> Self {
        let connections = Arc::new(Mutex::new(VecDeque::with_capacity(max_size)));
        let semaphore = Arc::new(Semaphore::new(max_size));
        
        Self {
            connections,
            max_size,
            semaphore,
            health_check_interval: Duration::from_secs(30),
        }
    }
    
    async fn get_connection(&self) -> Result<PooledConnection, PoolError> {
        let permit = self.semaphore.acquire().await?;
        
        let mut connections = self.connections.lock().await;
        
        // Try to find a healthy connection
        while let Some(mut conn) = connections.pop_front() {
            if conn.is_healthy && conn.last_used.elapsed() < Duration::from_secs(60) {
                drop(connections);
                return Ok(PooledConnection {
                    client: conn.client,
                    last_used: Instant::now(),
                    is_healthy: true,
                });
            }
        }
        
        drop(connections);
        
        // Create new connection
        let client = create_http2_client().await?;
        Ok(PooledConnection {
            client,
            last_used: Instant::now(),
            is_healthy: true,
        })
    }
    
    async fn return_connection(&self, mut conn: PooledConnection) {
        // Simple health check
        conn.is_healthy = self.check_health(&conn.client).await;
        conn.last_used = Instant::now();
        
        let mut connections = self.connections.lock().await;
        if connections.len() < self.max_size {
            connections.push_back(conn);
        }
        // Connection dropped if pool is full
    }
    
    async fn check_health(&self, client: &hyper::Client<HttpsConnector<HttpConnector>>) -> bool {
        // Implement health check logic
        true
    }
}
```

### Connection Sharing: Arc<Mutex> vs Channels

```rust
// Channel-based connection sharing (recommended for high concurrency)
struct ConnectionManager {
    connection_tx: mpsc::Sender<ConnectionRequest>,
}

enum ConnectionRequest {
    Borrow(Sender<PooledConnection>),
    Return(PooledConnection),
}

impl ConnectionManager {
    async fn new(pool_size: usize) -> Self {
        let (tx, mut rx) = mpsc::channel::<ConnectionRequest>(100);
        let connections = Arc::new(Mutex::new(VecDeque::new()));
        
        tokio::spawn(async move {
            while let Some(request) = rx.recv().await {
                match request {
                    ConnectionRequest::Borrow(response_tx) => {
                        let mut conns = connections.lock().await;
                        if let Some(conn) = conns.pop_front() {
                            let _ = response_tx.send(conn).await;
                        } else {
                            // Create new connection
                            let new_conn = create_connection().await;
                            let _ = response_tx.send(new_conn).await;
                        }
                    }
                    ConnectionRequest::Return(conn) => {
                        let mut conns = connections.lock().await;
                        if conns.len() < pool_size {
                            conns.push_back(conn);
                        }
                    }
                }
            }
        });
        
        Self { connection_tx: tx }
    }
    
    async fn borrow(&self) -> PooledConnection {
        let (tx, rx) = oneshot::channel();
        self.connection_tx.send(ConnectionRequest::Borrow(tx)).await.unwrap();
        rx.await.unwrap()
    }
}
```

## 3. Rate Limiting and Request Generation

### Token Bucket Implementation

```rust
use governor::{Quota, RateLimiter};
use governor::clock::{Clock, DefaultClock};
use governor::state::{InMemoryState, NotKeyed};
use std::num::NonZeroU32;
use std::time::Duration;

struct RateController {
    limiter: RateLimiter<NotKeyed, InMemoryState, DefaultClock>,
    burst_size: usize,
}

impl RateController {
    fn new(rps: u32, burst_multiplier: f32) -> Self {
        let quota = Quota::per_second(NonZeroU32::new(rps).unwrap())
            .allow_burst(NonZeroU32::new((rps as f32 * burst_multiplier) as u32).unwrap());
        
        let limiter = RateLimiter::direct(quota);
        
        Self {
            limiter,
            burst_size: (rps as f32 * burst_multiplier) as usize,
        }
    }
    
    async fn acquire(&self) {
        self.limiter.until_ready().await;
    }
    
    async fn acquire_n(&self, n: usize) {
        for _ in 0..n {
            self.limiter.until_ready().await;
        }
    }
}

// Coordinated omission-aware rate limiter
struct CoordinatedOmissionAwareLimiter {
    target_rps: u32,
    interval: Duration,
    last_send_time: Instant,
    stats: Arc<Mutex<Stats>>,
}

impl CoordinatedOmissionAwareLimiter {
    fn new(target_rps: u32) -> Self {
        let interval = Duration::from_nanos(1_000_000_000 / target_rps as u64);
        
        Self {
            target_rps,
            interval,
            last_send_time: Instant::now(),
            stats: Arc::new(Mutex::new(Stats::new())),
        }
    }
    
    async fn next_send_time(&mut self) -> Instant {
        let now = Instant::now();
        let mut stats = self.stats.lock().await;
        
        // Calculate when the next request should have been sent
        let next_theoretical = self.last_send_time + self.interval;
        
        if now >= next_theoretical {
            // We're behind schedule - record coordinated omission
            stats.record_omission(now.duration_since(next_theoretical));
            self.last_send_time = now;
            now
        } else {
            // We're on schedule
            self.last_send_time = next_theoretical;
            next_theoretical
        }
    }
}
```

### Accurate RPS Generation

```rust
use tokio::time::{interval_at, Instant};

struct RequestGenerator {
    target_rps: u32,
    batch_size: usize,
    stats_tx: mpsc::Sender<RequestStat>,
}

impl RequestGenerator {
    async fn run(&self) {
        let interval = Duration::from_nanos(1_000_000_000 / self.target_rps as u64);
        let mut interval = interval_at(Instant::now(), interval);
        
        let mut request_count = 0;
        let mut batch = Vec::with_capacity(self.batch_size);
        
        loop {
            interval.tick().await;
            
            // Create request
            let request = create_request();
            batch.push(request);
            request_count += 1;
            
            // Send batch if full
            if batch.len() >= self.batch_size {
                self.send_batch(batch.drain(..).collect()).await;
            }
            
            // Report statistics
            if request_count % 1000 == 0 {
                self.report_stats(request_count).await;
            }
        }
    }
    
    async fn send_batch(&self, batch: Vec<Request>) {
        // Distribute batch to workers
        for request in batch {
            // Send to worker pool
        }
    }
}
```

## 4. Backpressure Handling

### Bounded Channels and Semaphores

```rust
use tokio::sync::{mpsc, Semaphore};

struct BackpressureController {
    request_tx: mpsc::Sender<Request>,
    in_flight: Arc<Semaphore>,
    max_in_flight: usize,
    stats: Arc<Mutex<BackpressureStats>>,
}

impl BackpressureController {
    fn new(max_in_flight: usize, channel_buffer: usize) -> (Self, mpsc::Receiver<Request>) {
        let (tx, rx) = mpsc::channel(channel_buffer);
        let in_flight = Arc::new(Semaphore::new(max_in_flight));
        
        let controller = Self {
            request_tx: tx,
            in_flight,
            max_in_flight,
            stats: Arc::new(Mutex::new(BackpressureStats::new())),
        };
        
        (controller, rx)
    }
    
    async fn send_request(&self, request: Request) -> Result<(), BackpressureError> {
        // Acquire permit for in-flight request
        let permit = self.in_flight.try_acquire()?;
        
        // Send to channel (non-blocking)
        self.request_tx.try_send(request)?;
        
        // Release permit when request completes
        tokio::spawn(async move {
            // Process request...
            drop(permit); // Release permit
        });
        
        Ok(())
    }
    
    fn current_pressure(&self) -> f32 {
        let available = self.in_flight.available_permits();
        1.0 - (available as f32 / self.max_in_flight as f32)
    }
}
```

### Adaptive Backpressure

```rust
struct AdaptiveBackpressure {
    target_latency: Duration,
    max_concurrency: usize,
    current_concurrency: Arc<AtomicUsize>,
    adjustment_interval: Duration,
}

impl AdaptiveBackpressure {
    async fn adjust_concurrency(&self, current_latency: Duration) {
        let pressure = current_latency.as_secs_f32() / self.target_latency.as_secs_f32();
        
        if pressure > 1.2 {
            // Too much pressure, reduce concurrency
            let reduction = (self.max_concurrency as f32 * 0.1) as usize;
            self.current_concurrency.fetch_sub(reduction, Ordering::SeqCst);
        } else if pressure < 0.8 {
            // Underutilized, increase concurrency
            let increase = (self.max_concurrency as f32 * 0.05) as usize;
            self.current_concurrency.fetch_add(increase, Ordering::SeqCst);
        }
    }
}
```

## 5. Attack Orchestration Architecture

### Plugin/Trait System

```rust
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[async_trait]
trait AttackModule: Send + Sync {
    async fn execute(&self, config: &AttackConfig) -> Result<AttackResult, AttackError>;
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn config_schema(&self) -> serde_json::Value;
}

struct RapidResetAttack {
    max_streams: usize,
    reset_interval: Duration,
}

#[async_trait]
impl AttackModule for RapidResetAttack {
    async fn execute(&self, config: &AttackConfig) -> Result<AttackResult, AttackError> {
        // Implement HTTP/2 rapid reset attack
        Ok(AttackResult::default())
    }
    
    fn name(&self) -> &'static str {
        "rapid-reset"
    }
    
    fn description(&self) -> &'static str {
        "HTTP/2 Rapid Reset attack (CVE-2023-44487)"
    }
    
    fn config_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "max_streams": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 1000000
                },
                "reset_interval_ms": {
                    "type": "integer",
                    "minimum": 1
                }
            }
        })
    }
}

struct AttackOrchestrator {
    modules: HashMap<String, Box<dyn AttackModule>>,
    worker_pool: WorkerPool,
    config: Arc<AttackOrchestratorConfig>,
}

impl AttackOrchestrator {
    async fn execute_scenario(&self, scenario: AttackScenario) -> Result<ScenarioResult, OrchestratorError> {
        let mut tasks = JoinSet::new();
        let results = Arc::new(Mutex::new(Vec::new()));
        
        for attack in scenario.attacks {
            let module = self.modules.get(&attack.module)
                .ok_or(OrchestratorError::ModuleNotFound(attack.module.clone()))?;
            
            let results_clone = results.clone();
            let config = attack.config.clone();
            
            tasks.spawn(async move {
                match module.execute(&config).await {
                    Ok(result) => {
                        results_clone.lock().await.push((attack.name.clone(), result));
                    }
                    Err(e) => {
                        eprintln!("Attack {} failed: {:?}", attack.name, e);
                    }
                }
            });
        }
        
        while let Some(res) = tasks.join_next().await {
            res?;
        }
        
        Ok(ScenarioResult {
            attacks: results.lock().await.clone(),
            duration: scenario.duration,
        })
    }
}
```

### Configuration-Driven Scenarios

```yaml
# attack-scenario.yaml
name: "http2-stress-test"
duration: "5m"
concurrency: 10000
attacks:
  - name: "rapid-reset-main"
