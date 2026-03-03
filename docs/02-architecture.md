# HTTP/2 Core Architecture - Section 2: Streams, Multiplexing, HPACK, Flow Control, Server Push

## 1. Stream Lifecycle and State Machine

### 1.1 Stream States

HTTP/2 streams transition through a well-defined state machine with five primary states:

```
+--------+
|  idle  |  <-- All streams start here
+--------+
     |
     | send/receive HEADERS frame
     v
+--------+
|  open  |  <-- Stream is active
+--------+
     |
     | send END_STREAM flag
     v
+---------------------+
| half-closed (local) |  <-- Local side finished sending
+---------------------+
     |
     | receive END_STREAM flag
     v
+----------------------+
| half-closed (remote) |  <-- Remote side finished sending
+----------------------+
     |
     | both sides sent END_STREAM
     v
+--------+
| closed |  <-- Stream terminated
+--------+
```

### 1.2 Detailed State Transitions

**From IDLE state:**
- **→ OPEN**: When HEADERS frame is sent/received
- **→ RESERVED (local)**: When PUSH_PROMISE is sent
- **→ RESERVED (remote)**: When PUSH_PROMISE is received
- **→ CLOSED**: When RST_STREAM is sent/received

**From OPEN state:**
- **→ HALF-CLOSED (local)**: When END_STREAM flag sent
- **→ HALF-CLOSED (remote)**: When END_STREAM flag received
- **→ CLOSED**: When RST_STREAM sent/received

**From HALF-CLOSED states:**
- **→ CLOSED**: When END_STREAM received (for local) or sent (for remote)
- **→ CLOSED**: When RST_STREAM sent/received

### 1.3 Stream State Machine ASCII Diagram

```
                                    +--------+
                    send PP / recv PP |        |
                   ,------------------| reserved|
                   |                  | (remote)|
                   v                  +--------+
             +--------+                     |
             |        |                     | recv END_STREAM
             | reserved|                    | or RST_STREAM
             |  (local)|                    v
             +--------+               +--------+
                   |                  |        |
            recv H |                  |  half  |
               |   | send H           | closed |
               v   |                  | (remote)|
             +--------+               +--------+
             |        |                     |
             |   idle |                     | send RST_STREAM
             |        |                     v
             +--------+               +--------+
               |                      |        |
          send H |                    | closed |
               | | recv H             |        |
               v v                    +--------+
             +--------+
             |        |
             |  open  |
             |        |
             +--------+
               |     |
          send ES | | recv ES
               |     |
               v     v
        +----------+  +----------+
        |   half   |  |   half   |
        | closed   |  | closed   |
        | (local)  |  | (remote) |
        +----------+  +----------+
               |     |
          recv ES | | send ES
               |     |
               v     v
             +--------+
             |        |
             | closed |
             |        |
             +--------+
```

### 1.4 Stream Identifiers

- **31-bit unsigned integer** (0 to 2^31-1)
- **Client-initiated streams**: Odd-numbered (1, 3, 5, ...)
- **Server-initiated streams**: Even-numbered (2, 4, 6, ...)
- **Stream 0**: Reserved for connection control messages
- **Maximum stream ID**: 2^31-1 = 2,147,483,647

### 1.5 Reserved Streams

When server pushes resources:
- **PUSH_PROMISE frame** reserves a new stream
- Reserved stream starts in **RESERVED (remote)** state for client
- Reserved stream starts in **RESERVED (local)** state for server
- Stream transitions to OPEN when HEADERS frame sent

---

## 2. Multiplexing Deep Dive

### 2.1 Frame Interleaving Mechanism

HTTP/2 multiplexing works by interleaving frames from multiple streams on a single TCP connection:

```
TCP Connection Timeline:
┌─────────────────────────────────────────────────────┐
│ Frame Stream 1 │ Frame Stream 3 │ Frame Stream 1 │  │
│ Frame Stream 5 │ Frame Stream 3 │ Frame Stream 7 │  │
│ Frame Stream 1 │ Frame Stream 5 │ Frame Stream 3 │  │
└─────────────────────────────────────────────────────┘
```

**Frame Header Structure (9 bytes):**
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Length (24) = 0x00NNNNNN                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Type (8)    |   Flags (8)   |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                            Stream ID (31)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Frame Payload                       |
|                             ...                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 2.2 Stream Concurrency Limits

**SETTINGS_MAX_CONCURRENT_STREAMS** parameter controls maximum number of concurrently open streams:

- **Default**: No explicit limit (effectively unlimited)
- **Typical implementations**: 100-1000 streams
- **Client-side limit**: Advertised by server via SETTINGS frame
- **Server-side limit**: Advertised by client via SETTINGS frame

**Stream opening algorithm:**
1. Check if stream ID > previously opened stream ID
2. Verify stream ID parity matches initiator role
3. Ensure concurrent stream count < MAX_CONCURRENT_STREAMS
4. Allocate stream resources

### 2.3 Head-of-Line Blocking Mitigation

**HTTP/1.1 Problem:**
```
Request 1 ────────────────┐
Request 2 ────────────────────────────────┐
Request 3 ────────────────────────────────────────────────┐
                          ↑
                    Blocked by slow Response 1
```

**HTTP/2 Solution:**
```
Stream 1: ██████████████████████████████████████████████████████
Stream 3: ██████████████████████████████████████████████████████
Stream 5: ██████████████████████████████████████████████████████
          ↑ Each stream progresses independently
```

### 2.4 Frame Scheduling Algorithm

Implementations use various scheduling algorithms:

1. **Round-robin**: Simple but unfair
2. **Weighted fair queuing**: Based on stream priority weights
3. **Deficit round-robin**: Better fairness with variable frame sizes
4. **Priority-based**: Respects stream dependencies

**Example multiplexed frame sequence:**
```
Frame[type=HEADERS, stream=1, length=120]
Frame[type=DATA, stream=3, length=16384]
Frame[type=HEADERS, stream=5, length=80]
Frame[type=DATA, stream=1, length=8192]
Frame[type=DATA, stream=3, length=16384]
Frame[type=HEADERS, stream=7, length=60]
```

---

## 3. HPACK Compression Internals (RFC 7541)

### 3.1 Static Table (61 Entries)

The static table contains commonly used header fields with predefined indices:

```
Index | Header Name               | Header Value
------|---------------------------|----------------------
1     | :authority               | 
2     | :method                  | GET
3     | :method                  | POST
4     | :path                    | /
5     | :path                    | /index.html
6     | :scheme                  | http
7     | :scheme                  | https
8     | :status                  | 200
9     | :status                  | 204
10    | :status                  | 206
...   | ...                      | ...
41    | user-agent               | 
42    | vary                     | 
43    | via                      | 
44    | www-authenticate         | 
```

**Complete static table categories:**
- Pseudo-headers (:authority, :method, :path, :scheme, :status)
- Common request headers (accept, accept-encoding, etc.)
- Common response headers (age, cache-control, etc.)
- Security headers (strict-transport-security, etc.)

### 3.2 Dynamic Table Management

**Dynamic table characteristics:**
- **Maximum size**: SETTINGS_HEADER_TABLE_SIZE (default: 4096 bytes)
- **Eviction policy**: FIFO (First-In-First-Out)
- **Entry size calculation**: 32 + len(name) + len(value) bytes
- **Index range**: 62 to ∞ (static: 1-61)

**Table update operations:**
1. **Add entry**: When literal header with incremental indexing
2. **Evict entries**: When table size > max size
3. **Resize**: Via dynamic table size update

### 3.3 Huffman Encoding Tree

HPACK uses a static Huffman code optimized for HTTP header data:

**Key properties:**
- **Canonical Huffman code**: Codes assigned by code length
- **EOS (End-of-String) symbol**: 256 (not used in HTTP/2)
- **Code lengths**: 5 to 30 bits
- **Padding**: Last byte padded with 1 bits

**Example Huffman codes:**
```
Symbol | Code (binary)     | Length
-------|-------------------|-------
'a'    | 10110            | 5
'b'    | 1011110          | 7
'c'    | 010100           | 6
...    | ...              | ...
'EOS'  | 1111111111111111 | 30
```

### 3.4 Integer Encoding (Prefix-Based)

HPACK uses a variable-length integer encoding with a prefix:

**Encoding algorithm:**
1. Determine prefix length N (1-8 bits)
2. If value < 2^N - 1, encode in N bits
3. Else, encode 2^N - 1 in first N bits, then encode remainder in octets

**Prefix sizes by field type:**
- **Indexed header field**: N = 7
- **Literal header field with indexing**: N = 6
- **Literal header field without indexing**: N = 4
- **Literal header field never indexed**: N = 4
- **Dynamic table size update**: N = 5

### 3.5 Header Field Representations

**1. Indexed Header Field (7-bit prefix):**
```
  0   1   2   3   4   5   6   7
+---+---+---+---+---+---+---+---+
| 1 |        Index (7+)         |
+---+---------------------------+
```

**2. Literal Header Field with Incremental Indexing (6-bit prefix):**
```
  0   1   2   3   4   5   6   7
+---+---+---+---+---+---+---+---+
| 0 | 1 |      Index (6+)       |
+---+---+-----------------------+
| H |     Value Length (7+)     |
+---+---------------------------+
| Value String (Length octets)  |
+-------------------------------+
```

**3. Literal Header Field without Indexing (4-bit prefix):**
```
  0   1   2   3   4   5   6   7
+---+---+---+---+---+---+---+---+
| 0 | 0 | 0 | 0 |  Index (4+)   |
+---+---+---+---+---------------+
| H |     Value Length (7+)     |
+---+---------------------------+
| Value String (Length octets)  |
+-------------------------------+
```

**4. Literal Header Field Never Indexed (4-bit prefix):**
```
  0   1   2   3   4   5   6   7
+---+---+---+---+---+---+---+---+
| 0 | 0 | 0 | 1 |  Index (4+)   |
+---+---+---+---+---------------+
| H |     Value Length (7+)     |
+---+---------------------------+
| Value String (Length octets)  |
+-------------------------------+
```

### 3.6 Never-Indexed Headers

Headers marked as "never indexed" are sensitive and should not be:
- Stored by intermediaries
- Recompressed
- Added to dynamic tables

**Common never-indexed headers:**
- Authorization
- Cookie
- Set-Cookie
- Proxy-Authorization

---

## 4. Flow Control Mechanics

### 4.1 WINDOW_UPDATE Frame Format

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|X|                Window Size Increment (31)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **R flag**: Reserved (must be 0)
- **Window Size Increment**: Additional bytes receiver can accept
- **Stream ID**: 0 for connection, >0 for specific stream

### 4.2 Initial Window Size

- **Default**: 65,535 bytes (2^16 - 1)
- **Configurable via**: SETTINGS_INITIAL_WINDOW_SIZE
- **Maximum**: 2^31 - 1 bytes
- **Minimum**: 0 bytes (flow control disabled)

**Window size update rules:**
1. Window cannot exceed 2^31 - 1 bytes
2. Negative window results in FLOW_CONTROL_ERROR
3. Window updates are cumulative

### 4.3 Connection vs Stream Level Flow Control

**Two-tier flow control:**
```
Connection Window (65,535)
├── Stream 1 Window (16,384)
├── Stream 3 Window (32,768)
├── Stream 5 Window (8,192)
└── Stream 7 Window (8,192)
```

**Data transmission algorithm:**
1. Check connection window has capacity
2. Check specific stream window has capacity
3. Send DATA frame
4. Decrement both windows by frame length
5. Receiver sends WINDOW_UPDATE when ready for more data

### 4.4 Flow Control Deadlock Scenarios

**Scenario 1: Circular dependency**
```
Stream 1 waits for Stream 3 data
Stream 3 waits for Stream 1 data
Result: Deadlock
```

**Scenario 2: Window exhaustion**
```
Sender: Window = 0, cannot send WINDOW_UPDATE
Receiver: Waiting for data to process
Result: Deadlock
```

**Scenario 3: Priority inversion**
```
High-priority stream blocked by low-priority stream
Low-priority stream has no window space
Result: Priority inversion deadlock
```

**Prevention mechanisms:**
1. **Always maintain minimum window**: Keep some capacity
2. **Aggressive WINDOW_UPDATE**: Send updates before window exhausted
3. **Priority-aware scheduling**: Consider window availability in prioritization

### 4.5 Flow Control State Machine

```
+-------------+
|   Normal    |<-----------------------------------+
+-------------+                                    |
     |                                             |
     | Window reaches low watermark                |
     v                                             |
+-------------+                                    |
|  Near Zero  |-----> Send WINDOW_UPDATE ----------+
+-------------+                                    |
     |                                             |
     | Window exhausted                           |
     v                                             |
+-------------+                                    |
|  Exhausted  |-----> Block sending --------------+
+-------------+                                    |
     |                                             |
     | Receive WINDOW_UPDATE                      |
     v                                             |
+-------------+                                    |
|  Recovering |-----> Resume sending --------------+
+-------------+
```

---

## 5. Server Push Deep Dive

### 5.1 PUSH_PROMISE Frame Format

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|X|                 Promised Stream ID (31)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Header Block Fragment (*)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **R flag**: Reserved (must be 0)
- **Promised Stream ID**: Even-numbered stream for pushed response
- **Header Block Fragment**: Request headers for pushed resource

### 5.2 Server Push Sequence

```
Client                            Server
------                            ------
GET /index.html
  --->                           (Server analyzes /index.html)
                                  (Determines /style.css needed)
                                  
                                  PUSH_PROMISE[stream=1, promised=2]
                                  HEADERS[:path=/style.css]
                                  <---
                                  
                                  HEADERS[stream=2, :status=200]
                                  DATA[stream=2, css content]
                                  <---
                                  
HEADERS[stream=1, :status=200]   (Continues original response)
DATA[stream=1, html content]     --->
```

### 5.3 When Servers Use Push

**Optimal use cases:**
1. **Critical subresources**: CSS, JavaScript required for rendering
2. **Small static assets**: Icons, fonts, images
3. **API data dependencies**: JSON data needed for initial render
4. **Cacheable resources**: Resources with long TTL

**Anti-patterns:**
1. **Large resources**: May waste bandwidth
2. **Uncertain needs**: Client might not need resource
3. **Personalized content**: Different users need different resources
4. **Frequently changing content**: Cache invalidation issues

### 5.4 Browser Support Status (2024)

**Current browser support:**
- **Chrome**: Deprecated since version 106 (September 2022)
- **Firefox**: Disabled by default since version 90 (July 2021)
- **Safari**: Never implemented
- **Edge**: Follows Chrome (deprecated)
- **Opera**: Follows Chrome (deprecated)

**Why Chrome deprecated Server Push:**
1. **Poor adoption**: Only ~0.04% of sites used it effectively
2. **Implementation complexity**: Hard to get right
3. **Cache competition**: Pushed resources compete with explicit requests
4. **Bandwidth waste**: Often pushed unnecessary resources
5. **Better alternatives**: Preload, prefetch, Early Hints

### 5.5 Client Control Mechanisms

**SETTINGS_ENABLE_PUSH**: 
- Value 0: Push disabled
- Value 1: Push enabled (default)

**Stream reset (RST_STREAM)**:
- Client can reject pushed stream with error code REFUSED_STREAM
- Must be sent before any frames on promised stream

**Cache digest extension**:
- Experimental feature for smarter push decisions
- Client sends cache state to server
- Server avoids pushing already-cached resources

---

## 6. Stream Prioritization

### 6.1 Dependency Trees and Weights

**PRIORITY frame format:**
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|X|                Stream Dependency (31)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Weight (8)  |
+-+-+-+-+-+-+-+-+
```

- **E flag**: Exclusive dependency (1 bit)
- **Stream Dependency**: Parent stream ID (31 bits)
- **Weight**: Relative priority 1-256 (8 bits)

### 6.2 Exclusive Flag Behavior

**Without exclusive flag:**
```
Stream 5 depends on Stream 3 (weight=100)
Stream 7 depends on Stream 3 (weight=50)

Stream 3
├── Stream 5 (weight=100, 66.7% of resources)
└── Stream 7 (weight=50, 33.3% of resources)
```

**With exclusive flag:**
```
Stream 5 depends on Stream 3 exclusive (weight=100)
Stream 7 depends on Stream 3 (weight=50)

Stream 3
└── Stream 5 (weight=100, 100% of resources)
    └── Stream 7 (weight=50, 100% of Stream 5's resources)
```

### 6.3 Server Scheduling Algorithm (RFC 7540 Section 5.3)

**Resource allocation formula:**
```
share(stream) = weight(stream) / sum(weights of siblings)
```

**Scheduling algorithm steps:**
1. Build dependency tree from PRIORITY frames
2. Root is virtual stream 0
3. Calculate available resources per level
4. Allocate based on weights
5. Schedule frames from highest-priority ready streams

**Example calculation:**
```
Stream 1 (weight=200) -- 66.7%
├── Stream 3 (weight=100) -- 33.3% of parent = 22.2% total
└── Stream 5 (weight=50) -- 16.7% of parent = 11.1% total
Stream 7 (weight=100) -- 33.3%
```

### 6.4 Why Prioritization Was Deprecated (RFC 9113)

**Problems with HTTP/2 prioritization:**
1. **Implementation complexity**: Hard to implement correctly
2. **Inconsistent behavior**: Different servers implemented differently
3. **Lack of client control**: Browsers couldn't express complex priorities
4. **Ineffective in practice**: Often ignored by intermediaries
5. **TCP interference**: TCP congestion control overrides HTTP priorities

**RFC 9113 changes:**
- Removed PRIORITY frame
- Simplified to urgency/incidence model
- Better alignment with browser needs
- Reduced implementation complexity

### 6.5 Priority State Machine

```
+-------------+
|  No Parent  |<-----------------------------------+
+-------------+                                    |
     |                                             |
     | PRIORITY frame received                     |
     v                                             |
+-------------+                                    |
| Has Parent  |-----> Recalculate tree ------------+
+-------------+                                    |
     |                                             |
     | Parent stream closes                       |
     v                                             |
+-------------+                                    |
| Orphaned    |-----> Reparent to stream 0 --------+
+-------------+                                    |
     |                                             |
     | New PRIORITY frame                         |
     v                                             |
+-------------+                                    |
| Reparented  |-----> Update dependencies ---------+
+-------------+
```

---

## 7. SETTINGS Frame Parameters

### 7.1 SETTINGS Frame Format

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Identifier (16)         |          Value (32)           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Identifier (16)         |          Value (32)           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            ...                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 7.2 Complete SETTINGS Parameters

**1. SETTINGS_HEADER_TABLE_SIZE (0x1):**
- **Default**: 4096 bytes
- **Range**: 0 to 2^32-1
- **Purpose**: Maximum dynamic table size for HPACK
- **Impact**: Larger = better compression but more memory

**2. SETTINGS_ENABLE_PUSH (0x2):**
- **Default**: 1 (enabled)
- **Values**: 0 = disabled, 1 = enabled
- **Purpose**: Enable/disable server push
- **Note**: Major browsers now disable by default

**3. SETTINGS_MAX_CONCURRENT_STREAMS (0x3):**
- **Default**: No limit (effectively 2^31-1)
- **Range**: 0 to 2^31-1
- **Purpose**: Maximum open streams per connection
- **Typical values**: 100-1000

**4. SETTINGS_INITIAL_WINDOW_SIZE (0x4):**
- **Default**: 65535 bytes
- **Range**: 0 to 2^31-1
- **Purpose**: Initial flow control window size
- **Note**: Affects all existing streams when changed

**5. SETTINGS_MAX_FRAME_SIZE (0x5):**
- **Default**: 16384 bytes
- **Range**: 16384 to 2^24-1
- **Purpose**: Maximum frame payload size
- **Minimum**: 16384 (can't be smaller)

**6. SETTINGS_MAX_HEADER_LIST_SIZE (0x6):**
- **Default**: No limit (effectively infinite)
- **Range**: 0 to 2^32-1
- **Purpose**: Maximum uncompressed header list size
- **Security**: Prevents header bombing attacks

### 7.3 Settings Negotiation Protocol

**Two-phase negotiation:**
1. **Initial settings**: Sent in connection preface
2. **Acknowledgment**: SETTINGS frame with ACK flag set
3. **Dynamic updates**: Can be sent anytime
4. **Application**: Takes effect after acknowledgment

**ACK flag behavior:**
```
  0   1   2   3   4   5   6   7
+---+---+---+---+---+---+---+---+
| 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
+---+---+---+---+---+---+---+---+
|          Stream ID (31)        |
+---+---+---+---+---+---+---+---+
```

### 7.4 Settings State Diagram

```
+-------------+
|  Unacknowledged |<-----------------------------------+
+-------------+                                    |
     |                                             |
     | ACK received                               |
     v                                             |
+-------------+                                    |
|  Acknowledged |-----> Apply new values ----------+
+-------------+                                    |
     |                                             |
     | New SETTINGS frame                         |
     v                                             |
+-------------+                                    |
|  Pending    |-----> Send ACK --------------------+
+-------------+
```

---

## 8. CONTINUATION Frames

### 8.1 CONTINUATION Frame Format

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Header Block Fragment (*)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Type**: 0x9
- **Flags**: END_HEADERS (0x4)
- **Stream ID**: Must match preceding HEADERS/PUSH_PROMISE

### 8.2 Why CONTINUATION Frames Exist

**Problem:**
- HEADERS frames have limited payload size (MAX_FRAME_SIZE)
- Large header blocks need to be fragmented
- Need to maintain header block continuity

**Solution:**
- HEADERS frame without END_HEADERS flag starts block
- CONTINUATION frames continue the block
- Last CONTINUATION has END_HEADERS flag

### 8.3 Header Block Chaining Example

```
HEADERS Frame:
  Stream ID: 1
  Flags: 0x0 (no END_HEADERS)
  Length: 16384
  Payload: First 16384 bytes of header block

CONTINUATION Frame 1:
  Stream ID: 1
  Flags: 0x0
  Length: 8192
  Payload: Next 8192 bytes

CONTINUATION Frame 2:
  Stream ID: 1
  Flags: 0x4 (END_HEADERS)
  Length: 4096
  Payload: Final 4096 bytes
```

### 8.4 CONTINUATION Frame Rules

**Mandatory rules:**
1. Must follow HEADERS or PUSH_PROMISE without END_HEADERS
2. Must have same stream ID as preceding frame
3. No other frames can interleave in the chain
4. Last frame must have END_HEADERS flag

**Security considerations:**
1. **CONTINUATION flood**: Attackers send endless CONTINUATION frames
2. **Memory exhaustion**: Server must buffer entire header block
3. **Mitigation**: Limit maximum header block size

### 8.5 CONTINUATION State Machine

```
+-------------+
|  No Block   |<-----------------------------------+
+-------------+                                    |
     |                                             |
     | HEADERS without END_HEADERS                |
     v                                             |
+-------------+                                    |
| Building    |-----> Process CONTINUATION --------+
+-------------+                                    |
     |                                             |
     | CONTINUATION with END_HEADERS              |
     v                                             |
+-------------+                                    |
| Complete    |-----> Process header block --------+
+-------------+                                    |
     |                                             |
     | Error or timeout                           |
     v                                             |
+-------------+                                    |
|  Error      |-----> Send RST_STREAM ------------+
+-------------+
```

---

## 9. GOAWAY Frame - Graceful Shutdown

### 9.1 GOAWAY Frame Format

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|X|                 Last-Stream-ID (31)                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Error Code (32)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Additional Debug Data (*)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **R flag**: Reserved (must be 0)
- **Last-Stream-ID**: Highest-numbered stream processed
- **Error Code**: Reason for shutdown
- **Debug Data**: Optional human-readable debug info

### 9.2 Error Codes for GOAWAY

**Common error codes:**
- **NO_ERROR (0x0)**: Graceful shutdown
- **PROTOCOL_ERROR (0x1)**: Protocol violation detected
- **INTERNAL_ERROR (0x2)**: Implementation error
- **FLOW_CONTROL_ERROR (0x3)**: Flow control violation
- **SETTINGS_TIMEOUT (0x4)**: Settings acknowledgment timeout
- **STREAM_CLOSED (0x5)**: Frame received for closed stream
- **FRAME_SIZE_ERROR (0x6)**: Frame size incorrect
- **REFUSED_STREAM (0x7)**: Stream refused before processing
- **CANCEL (0x8)**: Stream cancelled
- **COMPRESSION_ERROR (0x9)**: HPACK compression error
- **CONNECT_ERROR (0xa)**: CONNECT method error
- **ENHANCE_YOUR_CALM (0xb)**: Excessive load
- **INADEQUATE_SECURITY (0xc)**: Insufficient security
- **HTTP_1_1_REQUIRED (0xd)**: HTTP/1.1 required

### 9.3 Graceful Shutdown Procedure

**Server-initiated shutdown:**
1. Send GOAWAY frame with Last-Stream-ID
2. Continue processing streams ≤ Last-Stream-ID
3. Reject new streams (ID > Last-Stream-ID)
4. Wait for client to acknowledge
5. Close connection after all streams complete

**Client response:**
1. Stop creating new streams
2. Complete processing of existing streams
3. Acknowledge GOAWAY (implicitly by closing)
4. Optionally open new connection

### 9.4 Last-Stream-ID Semantics

**Interpretation:**
- If Last-Stream-ID = 0: No streams processed
- If Last-Stream-ID = N: Streams 1..N might have been processed
- Streams > Last-Stream-ID: Definitely not processed
- Streams ≤ Last-Stream-ID: Might need retransmission

**Retry logic:**
```
if (stream_id <= last_stream_id) {
    // Might have been processed, check application state
    if (idempotent_operation) {
        retry_on_new_connection();
    } else {
        // Non-idempotent, cannot retry safely
        handle_as_error();
    }
} else {
    // Definitely not processed, safe to retry
    retry_on_new_connection();
}
```

### 9.5 Connection State Transitions with GOAWAY

```
+-------------+
|    Open     |<-----------------------------------+
+-------------+                                    |
     |                                             |
     | Send/Receive GOAWAY                        |
     v                                             |
+-------------+                                    |
|   Closing   |-----> Process existing streams ----+
+-------------+                                    |
     |                                             |
     | All streams complete                       |
     v                                             |
+-------------+                                    |
|   Closed    |-----> Terminate connection --------+
+-------------+                                    |
     |                                             |
     | Timeout or error                           |
     v                                             |
+-------------+                                    |
|  Aborted    |-----> Immediate close ------------+
+-------------+
```

---

## 10. Technical Implementation Details

### 10.1 Frame Processing Pipeline

```
Receive Frame → Parse Header → Validate → Route to Stream → Process
      ↑              ↑            ↑            ↑              ↑
   TCP Read     Frame Parser   Sanity Check  Stream Table  State Machine
```

**Critical sections:**
1. **Frame parser**: Must handle malformed frames gracefully
2. **Stream table**: Efficient lookup by stream ID
3. **State machines**: Per-stream and per-connection
4. **Flow control**: Window accounting and updates
5. **Priority scheduler**: Frame dispatch ordering

### 10.2 Memory Management Strategies

**Per-connection memory:**
- **Header compression tables**: Dynamic HPACK table
- **Stream state**: Per-stream metadata
- **Flow control windows**: Connection and stream windows
- **Buffer pools**: Frame buffering

**Per-stream memory:**
- **Header blocks**: During CONTINUATION sequence
- **Application data**: Buffered before delivery
- **Priority state**: Dependency tree nodes
- **Flow control**: Window counters

### 10.3 Performance Optimizations

**1. Zero-copy frame processing:**
- Parse frames in-place without copying
- Reference counted buffers
- Scatter/gather I/O

**2. Efficient stream lookup:**
- Hash table for active streams
- Array for small stream counts
- B-tree for large numbers of streams

**3. Batch frame sending:**
- Collect multiple frames before write
- TCP_NODELAY for last frame
- Nagle's algorithm consideration

**4. Header compression caching:**
- Share HPACK tables between connections
- Pre-warm static table
- Adaptive dynamic table sizing

### 10.4 Security Hardening

**Input validation:**
- Frame size limits
- Stream ID validation
- Header count limits
- Recursion depth limits

**Resource limits:**
- Maximum concurrent streams
- Maximum header list size
- Maximum frame size
- Connection timeout

**Attack mitigation:**
- Rate limiting per connection
- Early rejection of malformed frames
- Continuation frame limits
- HPACK bomb protection

### 10.5 Byte-Level Frame Examples

**DATA frame (stream 1, 1024 bytes, no padding):**
```
Length: 0x000400 (1024 decimal)
Type: 0x0 (DATA)
Flags: 0x0
Stream ID: 0x00000001
Payload: 1024 bytes of application data
```

**HEADERS frame (stream 3, with priority):**
```
Length: 0x000080 (128 decimal)
Type: 0x1 (HEADERS)
Flags: 0x24 (END_STREAM | END_HEADERS | PRIORITY)
Stream ID: 0x00000003
Payload: 
  Exclusive (1 bit): 0
  Stream Dependency (31 bits): 0x00000001
  Weight (8 bits): 0xFF (255)
  Header Block Fragment: 119 bytes
```

**SETTINGS frame (ACK):**
```
Length: 0x000000 (0 decimal)
Type: 0x4 (SETTINGS)
Flags: 0x1 (ACK)
Stream ID: 0x00000000
Payload: (empty)
```

### 10.6 HPACK Encoding Examples

**Indexed header field (index 2 = :method GET):**
```
Binary: 10000010
Hex: 0x82
```

**Literal header field with incremental indexing (name index 44, value "text/html"):**
```
First byte: 01011100 (0x5C) - 01 = incremental, 11100 = index 28
Second byte: 10001001 (0x89) - 1 = Huffman, 0001001 = length 9
Value: Huffman("text/html") = 9 bytes
```

**Dynamic table size update (max size 4096):**
```
Binary: 00111111 11110000 00000000
Hex: 0x3F 0xF0 0x00
```

---

## 11. Advanced Multiplexing Patterns

### 11.1 Stream Interleaving Patterns

**Optimal interleaving for latency:**
```
Small request headers → Large response data → Small request headers
```

**Poor interleaving (head-of-line blocking):**
```
Large request → Large response → Small request blocked
```

**Ideal frame sequence:**
```
HEADERS[stream=1, small] → HEADERS[stream=3, small] → 
DATA[stream=1, chunk] → DATA[stream=3, chunk] → 
HEADERS[stream=5, small] → DATA[stream=1, chunk] → ...
```

### 11.2 Flow Control Window Management

**Adaptive window sizing algorithm:**
```
window_size = max(min_window, 
                  last_good_window * (1 + growth_factor))
if (window_utilization < threshold) {
    decrease_window();
} else if (window_starved) {
    increase_window();
}
```

**Window update timing:**
- **Aggressive**: Send update at 50% window used
- **Conservative**: Send update at 90% window used
- **Adaptive**: Based on RTT and bandwidth estimation

### 11.3 Priority Implementation Strategies

**Server implementations:**
1. **nginx**: Simple round-robin, ignores priorities
2. **Apache**: Weighted fair queuing
3. **H2O**: Deficit round-robin with priorities
4. **Envoy**: Custom scheduler with dependency support

**Client (browser) priority schemes:**
- **Highest**: HTML, critical CSS/JS
- **High**: Fonts, above-fold images
- **Medium**: Other CSS/JS
- **Low**: Below-fold images, analytics

### 11.4 HPACK Optimization Techniques

**Dynamic table optimization:**
- **LRU eviction**: Least recently used entries
- **Size-based eviction**: Remove largest entries first
- **Frequency-based**: Keep frequently used entries
- **Hybrid**: Combination of above

**Header field reordering:**
- Static table indices first
- Frequently used dynamic entries next
- Literal encoding for rare headers
- Never-indexed for sensitive headers

---

## 12. Protocol Evolution and RFC 9113

### 12.1 Changes in RFC 9113 (HTTP/2 bis)

**Major changes:**
1. **Removed stream prioritization**: PRIORITY frame deprecated
2. **Simplified error handling**: Fewer error codes
3. **Clarified requirements**: Better implementation guidance
4. **Security improvements**: Stronger requirements

**Rationale:**
- Prioritization was rarely implemented correctly
- Added complexity without clear benefit
- Better approaches available (HTTP/3 QUIC priorities)

### 12.2 Comparison with HTTP/3

**HTTP/2 limitations addressed by HTTP/3:**
1. **TCP head-of-line blocking**: QUIC eliminates this
2. **Connection migration**: QUIC supports seamless migration
3. **Improved security**: Built-in TLS 1.3
4. **Better congestion control**: Per-stream congestion control

**HTTP/2 advantages retained:**
1. **Header compression**: HPACK still used
2. **Stream multiplexing**: Core concept preserved
3. **Server push**: Concept (though deprecated)
4. **Flow control**: Similar mechanisms

### 12.3 Implementation Statistics

**Adoption rates (2024):**
- **Websites using HTTP/2**: ~55-60%
- **HTTP/3 adoption**: ~25-30% and growing
- **Server push usage**: <0.1% (effectively zero)

**Performance impact:**
- **Median improvement**: 15-30% faster page loads
- **Best case**: 50%+ improvement for request-heavy sites
- **Worst case**: No improvement or slight regression

---

## 13. Debugging and Troubleshooting

### 13.1 Common Issues and Solutions

**Issue 1: Connection failures**
- **Cause**: Missing ALPN negotiation
- **Solution**: Ensure TLS 1.2+ with ALPN support

**Issue 2: Slow performance**
- **Cause**: TCP head-of-line blocking
- **Solution**: Implement HTTP/3 or optimize request ordering

**Issue 3: Memory exhaustion**
- **Cause**: Too many concurrent streams
- **Solution**: Reduce MAX_CONCURRENT_STREAMS limit

**Issue 4: Flow control deadlock**
- **Cause**: Window exhaustion
- **Solution**: Increase initial window size or implement better window management

### 13.2 Diagnostic Tools

**Command-line tools:**
- `curl --http2`: Test HTTP/2 support
- `nghttp`: HTTP/2 client and server
- `h2load`: HTTP/2 benchmarking tool
- `wireshark`: Packet analysis with HTTP/2 dissector

**Browser developer tools:**
- Network tab: Protocol column shows h2
- Waterfall view: Stream interleaving visualization
- Header view: HPACK compression analysis

### 13.3 Performance Metrics

**Key metrics to monitor:**
1. **Stream concurrency**: Average open streams
2. **Header compression ratio**: Bytes saved
3. **Flow control window utilization**: % of window used
4. **Frame interleaving efficiency**: Optimal vs actual
5. **Priority adherence**: Request vs actual scheduling

**Benchmarking methodology:**
1. Establish baseline with HTTP/1.1
2. Measure HTTP/2 performance
3. Compare key metrics
4. Identify optimization opportunities

---

## 14. Conclusion

HTTP/2 represents a fundamental shift in HTTP protocol design, moving from text-based to binary framing with native multiplexing. The core architecture components—streams, HPACK compression, flow control, and server push—work together to provide significant performance improvements over HTTP/1.1.

**Key takeaways:**
1. **Stream multiplexing** eliminates HTTP-level head-of-line blocking
2. **HPACK compression** reduces header overhead by 90%+
3. **Flow control** prevents receiver overload at application layer
4. **Server push**, while conceptually powerful, saw limited adoption
5. **Stream prioritization** was deprecated due to implementation complexity

**Future direction:**
HTTP/2 paved the way for HTTP/3, which addresses TCP-level head-of-line blocking through QUIC transport. While HTTP/3 adoption grows, HTTP/2 remains widely deployed and provides substantial benefits over HTTP/1.1 for most web applications.

The protocol's design reflects careful trade-offs between performance, complexity, and security, with ongoing evolution (RFC 9113) simplifying aspects that proved problematic in practice while maintaining core performance benefits.

---

## Appendix A: Frame Type Reference

| Type Value | Frame Type | Description |
|------------|------------|-------------|
| 0x0 | DATA | Carries message payload |
| 0x1 | HEADERS | Opens stream, carries headers |
| 0x2 | PRIORITY | Stream priority (deprecated) |
| 0x3 | RST_STREAM | Immediately terminates stream |
| 0x4 | SETTINGS | Connection parameters |
| 0x5 | PUSH_PROMISE | Server push promise |
| 0x6 | PING | Connection liveness test |
| 0x7 | GOAWAY | Connection shutdown |
| 0x8 | WINDOW_UPDATE | Flow control update |
| 0x9 | CONTINUATION | Continues header block |

## Appendix B: Error Code Reference

| Code | Name | Description |
|------|------|-------------|
| 0x0 | NO_ERROR | No error |
| 0x1 | PROTOCOL_ERROR | Protocol violation |
| 0x2 | INTERNAL_ERROR | Implementation error |
| 0x3 | FLOW_CONTROL_ERROR | Flow control violation |
| 0x4 | SETTINGS_TIMEOUT | Settings ACK timeout |
| 0x5 | STREAM_CLOSED | Frame for closed stream |
| 0x6 | FRAME_SIZE_ERROR | Invalid frame size |
| 0x7 | REFUSED_STREAM | Stream refused |
| 0x8 | CANCEL | Stream cancelled |
| 0x9 | COMPRESSION_ERROR | HPACK error |
| 0xa | CONNECT_ERROR | CONNECT method error |
| 0xb | ENHANCE_YOUR_CALM | Excessive load |
| 0xc | INADEQUATE_SECURITY | Insufficient security |
| 0xd | HTTP_1_1_REQUIRED | HTTP/1.1 required |

## Appendix C: HPACK Static Table (Partial)

Complete static table with 61 entries provides efficient encoding for common headers. The table includes pseudo-headers (:authority, :method, :path, :scheme, :status) and frequently used request/response headers.

## Appendix D: Detailed Byte Layout Examples

### D.1 Complete HEADERS Frame with Priority

```
Offset: 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
00000000: 00 00 64 01 24 00 00 00 03 00 00 00 01 FF 82 84   ..d.$........... 
00000010: 87 41 8C F1 E3 C2 E5 23 A6 BA 90 F4 FF 84 1D 75   .A.....#.......u
00000020: D0 62 0D 26 3D 4F 4E 74 17 A8 E1 96 26 94 33 38   .b.&=ONt....&.38
00000030: 25 2F 83 9D CA 83 60 72 2E 91 9D 29 58 53 9D 29   %/....`r...)XS.)
00000040: 70 1F 83 8E 9D 29 B0 1F 83 8E 9D 29 B0 58 85 1F   p....).....).X..
00000050: 83 8E 9D 29 B0 1F 83 8E 9D 29 B0 58 86 A2 B0 41   ...).....).X...A
00000060: 8A 08 9D 5C 0B 81 70 BE 58 86 A8 A2 B0 41 C4 8B   ...\..p.X....A..
00000070: 08 9D 5C 0B 80 00 00 00 00 00 00 00 00 00 00 00   ..\.............
```

**Breakdown:**
- **00 00 64**: Length = 100 bytes
- **01**: Type = HEADERS (0x01)
- **24**: Flags = END_STREAM (0x1) | END_HEADERS (0x4) | PRIORITY (0x20)
- **00 00 00 03**: Stream ID = 3
- **00 00 00 01**: Stream dependency = 1
- **FF**: Weight = 255
- Remaining: HPACK-encoded headers

### D.2 WINDOW_UPDATE Frame

```
Offset: 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
00000000: 00 00 04 08 00 00 00 00 00 00 40 00               ..........@.
```

**Breakdown:**
- **00 00 04**: Length = 4 bytes
- **08**: Type = WINDOW_UPDATE (0x08)
- **00**: Flags = 0
- **00 00 00 00**: Stream ID = 0 (connection-level)
- **00 00 40 00**: Window increment = 16384 bytes

### D.3 SETTINGS Frame with Parameters

```
Offset: 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
00000000: 00 00 18 04 00 00 00 00 00 00 01 00 00 10 00      ...............
00000010: 00 02 00 00 00 01 00 00 03 00 00 00 64 00 00 04   ............d...
00000020: 00 01 00 00 00 00 05 00 00 40 00 00 00 06 00 00   .........@......
00000030: 00 00                                             ..
```

**Breakdown:**
- **00 00 18**: Length = 24 bytes (6 settings × 4 bytes each)
- **04**: Type = SETTINGS (0x04)
- **00**: Flags = 0
- **00 00 00 00**: Stream ID = 0
- **00 01 00 00 10 00**: SETTINGS_HEADER_TABLE_SIZE = 4096
- **00 02 00 00 00 01**: SETTINGS_ENABLE_PUSH = 1
- **00 03 00 00 00 64**: SETTINGS_MAX_CONCURRENT_STREAMS = 100
- **00 04 00 01 00 00**: SETTINGS_INITIAL_WINDOW_SIZE = 65536
- **00 05 00 00 40 00**: SETTINGS_MAX_FRAME_SIZE = 16384
- **00 06 00 00 00 00**: SETTINGS_MAX_HEADER_LIST_SIZE = unlimited

## Appendix E: Optimization Techniques

### E.1 HPACK Dynamic Table Management

**Optimal eviction strategy:**
```python
def evict_entries(table, max_size):
    current_size = sum(32 + len(name) + len(value) for name, value in table)
    while current_size > max_size:
        # Remove least frequently used entry
        lfu_entry = min(table, key=lambda x: x.frequency)
        table.remove(lfu_entry)
        current_size -= (32 + len(lfu_entry.name) + len(lfu_entry.value))
```

**Header field frequency tracking:**
- **Hot entries**: Keep in dynamic table
- **Warm entries**: Consider for eviction
- **Cold entries**: First candidates for eviction
- **Never-indexed**: Never add to table

### E.2 Flow Control Window Optimization

**Adaptive window algorithm:**
```python
class AdaptiveFlowControl:
    def __init__(self):
        self.window = 65535
        self.utilization_history = []
        self.rtt = 100  # ms
        self.bandwidth = 1_000_000  # bps
        
    def calculate_optimal_window(self):
        # BDP = Bandwidth-Delay Product
        bdp = (self.bandwidth * self.rtt / 1000) / 8  # bytes
        optimal = max(65535, int(bdp * 1.5))  # 1.5x BDP for safety
        return min(optimal, 2**31 - 1)  # Max HTTP/2 window
```

### E.3 Stream Scheduling Algorithm

**Weighted deficit round-robin:**
```python
def schedule_streams(streams):
    for stream in streams:
        stream.deficit += stream.weight
    
    # Sort by deficit (highest first)
    streams.sort(key=lambda s: s.deficit, reverse=True)
    
    # Schedule frames from stream with highest deficit
    scheduled = streams[0]
    frame_size = min(scheduled.deficit, MAX_FRAME_SIZE)
    scheduled.deficit -= frame_size
    
    return scheduled, frame_size
```

---

## Appendix F: Security Considerations Deep Dive

### F.1 CONTINUATION Flood Protection

**Implementation strategy:**
```python
class ContinuationProtection:
    def __init__(self):
        self.max_header_block_size = 65536  # 64KB
        self.max_continuation_frames = 100
        self.timeout_ms = 10000  # 10 seconds
        
    def check_continuation(self, stream_id, frame_count, block_size):
        if frame_count > self.max_continuation_frames:
            raise ProtocolError("Too many CONTINUATION frames")
        if block_size > self.max_header_block_size:
            raise ProtocolError("Header block too large")
        # Reset timer for this stream
        self.reset_timer(stream_id)
```

### F.2 HPACK Bomb Mitigation

**Dynamic table size limits:**
- **Absolute maximum**: 65536 bytes (though spec allows more)
- **Per-connection limit**: Based on available memory
- **Growth rate limiting**: Gradual increase, not sudden jumps
- **Eviction under pressure**: Aggressive eviction when memory low

### F.3 Rapid Reset Attack Countermeasures

**Rate limiting strategy:**
```python
class RapidResetProtection:
    def __init__(self):
        self.resets_per_second = 100  # Max resets/second
        self.reset_times = []
        
    def check_reset(self, stream_id):
        now = time.time()
        # Remove old entries
        self.reset_times = [t for t in self.reset_times if now - t < 1.0]
        
        if len(self.reset_times) >= self.resets_per_second:
            # Too many resets, close connection
            raise ConnectionError("Excessive stream resets")
        
        self.reset_times.append(now)
```

---

*Document compiled from RFC 7540, RFC 7541, RFC 9113, implementation documentation, performance analysis studies, and security advisories. Includes original analysis and optimization recommendations. Last updated: March 2024.*