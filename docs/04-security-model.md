# HTTP/2 Security Model - Section 4: TLS, Security Architecture, Cipher Suites

## 1. TLS + HTTP/2: Mandatory Encryption and ALPN Negotiation

### 1.1 Browser TLS Requirement for HTTP/2
While the HTTP/2 specification (RFC 7540) does not mandate TLS for HTTP/2, all major browser implementations (Chrome, Firefox, Safari, Edge) require TLS for HTTP/2 connections. This decision was made for several security and practical reasons:

1. **Protocol Ossification Prevention**: TLS prevents middleboxes from inspecting and modifying HTTP/2 frames, which could lead to protocol ossification where intermediaries break new protocol features.

2. **Header Compression Security**: HPACK (HTTP/2 header compression) has known security vulnerabilities when used over cleartext, particularly compression oracle attacks like CRIME and BREACH.

3. **Multiplexing Security**: Without encryption, attackers could more easily inject frames or manipulate stream priorities.

4. **Push Promise Security**: Server push mechanisms are more secure when authenticated via TLS.

### 1.2 ALPN Extension (RFC 7301) Deep Dive
The Application-Layer Protocol Negotiation (ALPN) extension is critical for HTTP/2 over TLS negotiation:

**ALPN Handshake Flow:**
```
ClientHello
  - extension: application_layer_protocol_negotiation(16)
  - protocol_name_list: ["h2", "http/1.1"]
  
ServerHello
  - extension: application_layer_protocol_negotiation(16)
  - protocol_name: "h2"
```

**Technical Details:**
- ALPN extension type: 16 (0x10)
- Protocol identifiers: "h2" for HTTP/2 over TLS, "h2c" for HTTP/2 cleartext
- Negotiation occurs during TLS handshake, before application data exchange
- Allows servers to select appropriate certificate based on negotiated protocol

**ALPN vs NPN:**
ALPN succeeded NPN (Next Protocol Negotiation) which was a TLS extension proposed by Google for SPDY. ALPN is standardized in RFC 7301 while NPN was never standardized.

### 1.3 HTTP/2 Connection Establishment over TLS
The complete HTTP/2 over TLS establishment sequence:

1. **TCP Connection**: Client establishes TCP connection to server on port 443
2. **TLS Handshake**: Client sends ClientHello with ALPN extension indicating "h2" support
3. **ALPN Negotiation**: Server responds with ServerHello selecting "h2"
4. **TLS Completion**: TLS handshake completes with cipher suite establishment
5. **HTTP/2 Preface**: Client sends connection preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
6. **SETTINGS Exchange**: Both sides exchange SETTINGS frames

## 2. Cipher Suite Blacklist (RFC 7540 Appendix A)

### 2.1 Prohibited Cipher Suites
RFC 7540 Appendix A explicitly prohibits the following TLS 1.2 cipher suites for HTTP/2:

```
TLS_NULL_WITH_NULL_NULL
TLS_RSA_WITH_NULL_MD5
TLS_RSA_WITH_NULL_SHA
TLS_RSA_EXPORT_WITH_RC4_40_MD5
TLS_RSA_WITH_RC4_128_MD5
TLS_RSA_WITH_RC4_128_SHA
TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
TLS_RSA_WITH_IDEA_CBC_SHA
TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
TLS_RSA_WITH_DES_CBC_SHA
TLS_RSA_WITH_3DES_EDE_CBC_SHA
TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA
TLS_DH_DSS_WITH_DES_CBC_SHA
TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA
TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA
TLS_DH_RSA_WITH_DES_CBC_SHA
TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA
TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
TLS_DHE_DSS_WITH_DES_CBC_SHA
TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
TLS_DHE_RSA_WITH_DES_CBC_SHA
TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
TLS_DH_anon_EXPORT_WITH_RC4_40_MD5
TLS_DH_anon_WITH_RC4_128_MD5
TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA
TLS_DH_anon_WITH_DES_CBC_SHA
TLS_DH_anon_WITH_3DES_EDE_CBC_SHA
```

### 2.2 Rationale for Blacklisting
These cipher suites are prohibited due to:

1. **Weak Encryption Algorithms**: NULL, RC4, DES, 3DES, IDEA
2. **Export-grade Cryptography**: 40-bit and 56-bit keys vulnerable to brute force
3. **Lack of Forward Secrecy**: Static RSA key exchange
4. **Weak Hash Functions**: MD5, SHA-1 vulnerabilities
5. **Anonymous Diffie-Hellman**: No authentication, vulnerable to MITM

### 2.3 Minimum Required Cipher Suite
RFC 7540 Section 9.2.2 mandates that HTTP/2 implementations MUST support:
```
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
```

**Technical Specification:**
- **Key Exchange**: ECDHE_RSA using P-256 (secp256r1) or better curve
- **Authentication**: RSA with minimum 2048-bit key
- **Encryption**: AES-128 in GCM mode (Galois/Counter Mode)
- **Hash**: SHA-256 for PRF and certificate verification
- **TLS Version**: TLS 1.2 or higher

**Cryptographic Details:**
```
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 =
  Key Exchange:    ECDHE (Ephemeral Elliptic Curve Diffie-Hellman)
  Authentication:  RSA (Rivest-Shamir-Adleman)
  Encryption:      AES-128-GCM (Advanced Encryption Standard 128-bit)
  MAC:             Integrated via GCM authentication tag
  PRF:             SHA-256 (Secure Hash Algorithm 256-bit)
```

**Security Properties:**
1. **Forward Secrecy**: Ephemeral ECDHE keys discarded after session
2. **Authenticated Encryption**: GCM provides confidentiality and integrity
3. **Modern Cryptography**: All components are post-quantum resistant to known attacks
4. **Performance**: Hardware-accelerated AES-GCM on modern CPUs

**Implementation Requirements:**
```c
// OpenSSL example of required cipher suite
SSL_CTX* ctx = SSL_CTX_new(TLS_method());
SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");

// Minimum TLS version
SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

// Required curves for ECDHE
SSL_CTX_set1_curves_list(ctx, "P-256:X25519:P-384:P-521");
```

**Alternative Strong Cipher Suites:**
While only one is mandatory, implementations should support:
```
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
```

**TLS 1.3 Equivalent:**
In TLS 1.3, the mandatory cipher suite is:
```
TLS_AES_128_GCM_SHA256
```
Which provides equivalent security with simplified handshake.

**Compliance Verification:**
Servers can be tested using:
```bash
# Using OpenSSL s_client
openssl s_client -connect example.com:443 -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256

# Using nmap
nmap --script ssl-enum-ciphers -p 443 example.com

# Using testssl.sh
testssl.sh --protocols --cipher-per-proto example.com:443
```

This cipher suite provides:
- **Forward Secrecy**: Ephemeral Elliptic Curve Diffie-Hellman (ECDHE)
- **Strong Encryption**: AES-128 in GCM mode (authenticated encryption)
- **Modern Hash**: SHA-256
- **RSA Authentication**: Server authentication via RSA certificates

## 3. TLS 1.2 vs TLS 1.3 with HTTP/2

### 3.1 TLS 1.2 Features for HTTP/2
TLS 1.2 (RFC 5246) with HTTP/2 requires:
- ALPN extension support
- SNI (Server Name Indication) support
- Forward secrecy cipher suites (ECDHE or DHE)
- AEAD cipher modes (GCM, CCM, ChaCha20-Poly1305)

### 3.2 TLS 1.3 Advantages with HTTP/2
TLS 1.3 (RFC 8446) provides significant improvements:

**Reduced Handshake Latency:**
- 1-RTT handshake (vs 2-RTT in TLS 1.2)
- 0-RTT resumption for subsequent connections

**Enhanced Security:**
- Removed insecure features (compression, renegotiation, static RSA)
- All cipher suites provide forward secrecy
- Mandatory server certificate verification

**0-RTT Implications for HTTP/2:**

**Technical Implementation:**
```
TLS 1.3 0-RTT Handshake with HTTP/2:
Client                                              Server

ClientHello
  + early_data
  + psk_key_exchange_modes
  + pre_shared_key
  + ALPN: ["h2"]
  (0-RTT Application Data) -------->
                                    ServerHello
                                    + pre_shared_key
                                    + ALPN: ["h2"]
                                    EncryptedExtensions
                                    Finished
                                    [Application Data] <-------->
                                    <-------- [Application Data]
```

**Security Considerations:**

1. **Replay Attacks**: 0-RTT data can be replayed by attackers
   ```http
   // Replayable 0-RTT request
   GET /api/transfer?amount=100&to=attacker HTTP/2
   Authorization: Bearer <token>
   
   // Attacker captures and replays
   ```

2. **HTTP/2 Specific Mitigations**:
   - **Stream IDs**: Prevent request reordering attacks
   - **SETTINGS Frame**: Early data limits via SETTINGS_MAX_EARLY_DATA
   - **Connection Management**: Reject 0-RTT on new connections

3. **Implementation Requirements**:
   ```go
   // Go example: 0-RTT validation
   func handleEarlyData(earlyData []byte) error {
       // Validate request idempotency
       if !isIdempotent(earlyData) {
           return errors.New("non-idempotent request in 0-RTT")
       }
       
       // Check replay protection
       if isReplay(earlyData) {
           return errors.New("replay detected")
       }
       
       // Apply rate limiting
       if exceedsRateLimit(earlyData) {
           return errors.New("0-RTT rate limit exceeded")
       }
       
       return nil
   }
   ```

4. **RFC 8470 Guidelines for HTTP/2 0-RTT**:
   - **Idempotent Requests Only**: GET, HEAD, OPTIONS, PUT, DELETE
   - **Non-idempotent Prohibition**: POST, PATCH must not use 0-RTT
   - **Stateful Operations**: Session creation, authentication excluded
   - **Side Effects**: Requests with side effects must be protected

5. **Replay Protection Mechanisms**:
   - **Single-Use Tickets**: TLS session tickets used once
   - **Client Random**: Incorporate ClientHello.random
   - **Timestamp Validation**: Reject old tickets
   - **Server State**: Maintain replay window (recommended: 2^16 packets)

6. **HTTP/2 Frame Restrictions for 0-RTT**:
   ```
   Allowed in 0-RTT:            Not allowed in 0-RTT:
   - HEADERS (idempotent)       - HEADERS (non-idempotent)
   - DATA                       - RST_STREAM
   - WINDOW_UPDATE              - PRIORITY
   - SETTINGS                   - PUSH_PROMISE
   ```

**Recommendation**: 
- Non-idempotent requests should not use 0-RTT
- Implement replay detection mechanisms
- Use SETTINGS_MAX_EARLY_DATA to limit 0-RTT data
- Monitor 0-RTT usage for abuse patterns
- Consider disabling 0-RTT for sensitive applications

### 3.3 TLS 1.3 Cipher Suites for HTTP/2
TLS 1.3 simplified cipher suites:
```
TLS_AES_128_GCM_SHA256
TLS_AES_256_GCM_SHA384
TLS_CHACHA20_POLY1305_SHA256
TLS_AES_128_CCM_SHA256
TLS_AES_128_CCM_8_SHA256
```

All provide forward secrecy by design.

## 4. Connection Coalescing Security

### 4.1 Connection Coalescing Mechanism
HTTP/2 allows multiple origins to share a single connection when:
1. **Same IP Address**: Origins resolve to same IP
2. **Certificate SAN**: Server certificate contains all origin names in Subject Alternative Names
3. **Protocol Support**: Both origins support HTTP/2

**Example:**
```
Origin A: https://www.example.com
Origin B: https://static.example.com
Certificate SAN: DNS:www.example.com, DNS:static.example.com
→ Can share same HTTP/2 connection
```

### 4.2 Security Implications

**Positive Security Aspects:**
- Reduced connection establishment overhead
- Fewer TLS handshakes reduce attack surface
- Consistent security context across origins

**Security Risks:**
1. **Certificate Scope Validation**: Must validate all SAN entries
2. **Origin Isolation**: Cookies and credentials must be properly scoped
3. **Mixed Content**: Coalesced connections can bypass mixed content warnings
4. **HPACK Context Sharing**: Compression contexts shared across origins

**Mitigations:**
- Strict certificate validation
- Origin header validation
- Separate HPACK contexts per origin (not implemented in practice)

## 5. Certificate Pinning with HTTP/2

### 5.1 HPKP (HTTP Public Key Pinning)
HTTP Public Key Pinning was a mechanism to pin certificate public keys:
```
Public-Key-Pins: pin-sha256="base64=="; max-age=5184000
```

**HTTP/2 Considerations:**
- Header compression reduces overhead of pinning headers
- Multiplexing requires consistent pinning across all streams
- Connection coalescing complicates pinning validation

### 5.2 Modern Alternatives
HPKP was deprecated due to risks of bricking sites. Modern approaches:

**Certificate Transparency (CT):**
- Public logs of all certificates
- Browsers require CT for Extended Validation certificates
- HTTP/2 headers can include SCT (Signed Certificate Timestamp)

**Expect-CT Header:**
```
Expect-CT: max-age=86400, enforce, report-uri="https://example.com/report"
```

**CAA (Certificate Authority Authorization):**
DNS records specifying which CAs can issue certificates for a domain.

## 6. HTTP/2 Cleartext (h2c)

### 6.1 h2c Specification
HTTP/2 cleartext (h2c) is defined in RFC 7540 Section 3.2 for "http" URIs:

**Upgrade Mechanism:**
```
GET / HTTP/1.1
Host: server.example.com
Connection: Upgrade, HTTP2-Settings
Upgrade: h2c
HTTP2-Settings: <base64url encoding of SETTINGS payload>
```

**Direct Mechanism**: Connection starts with HTTP/2 connection preface:
```
Client sends immediately: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
```

**Technical Implementation Details:**

**HTTP/1.1 Upgrade Request:**
```http
GET / HTTP/1.1
Host: example.com
Connection: Upgrade, HTTP2-Settings
Upgrade: h2c
HTTP2-Settings: AAEAAEAAAAIAAAABAAMAAABkAAQBAAAAAAUAAEAA
```

**Base64url-encoded SETTINGS Frame:**
```
Decoded SETTINGS (hex): 00 00 00 00 00 00 00 04 00 00 00 64 00 01 00 00 00 05 00 00 00 00
Frame: SETTINGS
  SETTINGS_HEADER_TABLE_SIZE: 4096
  SETTINGS_ENABLE_PUSH: 1
  SETTINGS_MAX_CONCURRENT_STREAMS: 100
  SETTINGS_INITIAL_WINDOW_SIZE: 65535
  SETTINGS_MAX_FRAME_SIZE: 16384
  SETTINGS_MAX_HEADER_LIST_SIZE: unlimited
```

**Server Response:**
```http
HTTP/1.1 101 Switching Protocols
Connection: Upgrade
Upgrade: h2c
```

### 6.2 Browser Non-Support Rationale
Browsers don't support h2c due to critical security vulnerabilities:

1. **HPACK Security Vulnerabilities**:
   - **CRIME Attack** (Compression Ratio Info-leak Made Easy): 
     ```python
     # CRIME attack principle
     def crime_attack(compressed_size):
         # Attacker observes compression ratio changes
         # to infer secret values in headers
         if compressed_size_decreases:
             return "Secret character guessed correctly"
     ```
   
   - **BREACH Attack** (Browser Reconnaissance and Exfiltration via Adaptive Compression of Hypertext):
     ```http
     # BREACH exploits HTTP response compression
     GET /search?q=<guess> HTTP/2
     Response: <html>...CSRF token: SECRET_VALUE...</html>
     # Compression ratio reveals if guess matches SECRET_VALUE
     ```
   
   - **TIME Attack**: Timing analysis of compression operations

2. **HPACK-specific Attacks**:
   ```http
   # HPACK dynamic table poisoning
   Header: :method: GET
   Header: :path: /search?q=AAAAAAAAAAAAAAAAAAAAAA
   Header: cookie: session=SECRET
   
   # Attacker observes table index assignments
   # to infer header values
   ```

3. **Middlebox Interference**:
   - **Protocol Ossification**: Middleboxes may modify or drop unknown frames
   - **Header Manipulation**: Proxies add, remove, or modify headers
   - **Flow Control Interference**: Middleboxes may not understand WINDOW_UPDATE

4. **Header Injection Vulnerabilities**:
   ```http
   # Without TLS, attackers can inject frames
   Malicious Middlebox Injection:
     Original: HEADERS frame (stream 1)
     Injected: HEADERS frame (stream 3) with malicious headers
   ```

5. **Lack of Authentication**:
   - No server certificate validation
   - No client authentication
   - Vulnerable to MITM attacks

### 6.3 Security Mitigations for h2c (When Used)

**When h2c must be used (internal networks):**

1. **Network Segmentation**:
   ```bash
   # Isolate h2c traffic
   iptables -A INPUT -p tcp --dport 80 -s 10.0.0.0/8 -j ACCEPT
   iptables -A INPUT -p tcp --dport 80 -j DROP
   ```

2. **HPACK Protection**:
   ```go
   // Disable dynamic table for sensitive headers
   func shouldIndexHeader(name, value string) bool {
       sensitiveHeaders := []string{"cookie", "authorization", "x-csrf-token"}
       for _, h := range sensitiveHeaders {
           if strings.EqualFold(name, h) {
               return false  // Never index sensitive headers
           }
       }
       return true
   }
   ```

3. **Frame Validation**:
   ```python
   def validate_h2c_frame(frame):
       # Reject potentially dangerous frames in cleartext
       if frame.type == FrameType.PUSH_PROMISE:
           raise SecurityError("PUSH_PROMISE not allowed in h2c")
       
       if frame.type == FrameType.PRIORITY:
           # Validate priority dependencies
           if frame.depends_on == 0:
               raise SecurityError("Invalid priority stream")
   ```

4. **Rate Limiting**:
   ```nginx
   # nginx configuration for h2c security
   http {
       limit_req_zone $binary_remote_addr zone=h2c:10m rate=10r/s;
       
       server {
           listen 80 http2;  # h2c
           
           location / {
               limit_req zone=h2c burst=20;
               # Additional security headers
               add_header X-Content-Type-Options nosniff;
               add_header X-Frame-Options DENY;
           }
       }
   }
   ```

### 6.3 h2c Use Cases
Despite browser limitations, h2c is used in:

**Internal Microservices:**
- Service-to-service communication within trusted networks
- API gateways to backend services
- Container orchestration (Kubernetes sidecars)

**Proxies and Load Balancers:**
- HTTP/2 between proxy and origin server
- Translation from HTTP/1.1 client to HTTP/2 backend

**Development and Testing:**
- Local development servers
- Performance testing without TLS overhead

## 7. ALPN Negotiation Attack Surface

### 7.1 ALPN Downgrade Attacks
Attackers could force ALPN negotiation to select weaker protocol:

**Attack Vectors:**
1. **Middlebox Interference**: Modify ClientHello to remove "h2" from protocol list
2. **Server Misconfiguration**: Servers preferring older protocols
3. **Protocol Confusion**: Different interpretations of protocol identifiers
4. **Version Intolerance**: Servers rejecting unknown protocols causing fallback

**Technical Implementation of Downgrade:**
```
// Malicious middlebox manipulation
Original ClientHello:
  ALPN: ["h2", "http/1.1"]
Modified ClientHello:
  ALPN: ["http/1.1"]  // h2 removed

// Server misconfiguration
Server ALPN selection logic:
  if ("h2" in client_protocols and server.supports_h2):
    return "h2"
  else if ("http/1.1" in client_protocols):
    return "http/1.1"  // Fallback even if h2 available
```

**Mitigations:**
- TLS must be used to protect ALPN negotiation
- Clients should abort if preferred protocol not selected (TLS alert 120)
- Implementations must validate protocol identifiers strictly
- Use TLS 1.3 which has built-in downgrade protection

### 7.2 ALPN Confusion Attacks
**Cross-protocol Attacks:**
- Attacker convinces client that server supports different protocol
- Example: HTTP/2 client connects to SMTP server supporting ALPN
- Protocol mismatch leading to security bypass

**Specific Attack Scenarios:**
1. **Protocol Impersonation**: Server claims to support "h2" but implements different protocol
2. **Feature Confusion**: Different interpretations of frame types across protocols
3. **State Machine Attacks**: Mismatched state transitions between protocols

**Mitigation:**
- Protocol-specific validation after handshake
- Application-layer protocol confirmation via magic bytes
- Strict frame validation according to RFC 7540
- Implement protocol fingerprinting checks

### 7.3 Implementation Vulnerabilities

**Buffer Overflows**: 
```c
// Vulnerable ALPN parsing
void parse_alpn(uint8_t* data, size_t len) {
    uint8_t protocol_len = data[0];
    char protocol[256];
    memcpy(protocol, data + 1, protocol_len);  // No bounds check
    protocol[protocol_len] = '\0';
}
```

**Memory Exhaustion**: 
- Large protocol lists (max 2^16-1 bytes) causing denial of service
- Recursive protocol name parsing vulnerabilities
- Protocol name duplication attacks

**Timing Attacks**: 
- Side channels in protocol selection logic
- String comparison timing differences
- Memory access patterns revealing selected protocol

**Specific CVEs Related to ALPN:**
- CVE-2016-6309: OpenSSL ALPN memory exhaustion
- CVE-2018-0732: OpenSSL timing attack in ALPN
- CVE-2019-1551: ALPN buffer overread in OpenSSL

### 7.4 ALPN Security Best Practices

**Client Implementation:**
```python
def validate_alpn_negotiation(client_protocols, server_selected):
    # Validate server selection is in client list
    if server_selected not in client_protocols:
        raise TLSAlert(120)  # no_application_protocol
    
    # Prefer modern protocols
    preferred_order = ["h2", "http/1.1"]
    if server_selected != preferred_order[0]:
        log_warning(f"Protocol downgrade: {server_selected}")
    
    # Validate protocol identifier format
    if not (1 <= len(server_selected) <= 255):
        raise TLSAlert(47)  # illegal_parameter
```

**Server Implementation:**
- Maintain secure protocol preference order
- Implement protocol-specific security checks
- Log all ALPN negotiations for audit
- Support protocol fallback with security considerations

**Network-Level Protections:**
- Use TLS 1.3 with downgrade sentinel
- Implement ALPN consistency checks
- Monitor for protocol downgrade patterns
- Deploy intrusion detection for ALPN manipulation

## 8. HTTP/2 and Intermediaries (Proxies)

### 8.1 Proxy Translation Models

**HTTP/1.1 to HTTP/2 Translation:**
```
Client (HTTP/1.1) → Proxy → Server (HTTP/2)
```
- Proxy maintains separate connections
- Header translation required
- Flow control translation complex

**HTTP/2 to HTTP/1.1 Translation:**
```
Client (HTTP/2) → Proxy → Server (HTTP/1.1)
```
- Multiplexing to serial translation
- Priority mapping challenges
- Server push cannot be translated

### 8.2 Security Implications

**Header Manipulation:**
- Proxies may add, remove, or modify headers
- HPACK compression context not preserved
- Security headers may be stripped

**TLS Termination:**
- Proxy becomes TLS termination point
- Certificate validation responsibility shifts
- End-to-end encryption broken

**Authentication Bypass:**
- Improper header forwarding
- Cookie manipulation
- Authorization header stripping

### 8.3 Secure Proxy Deployment

**Best Practices:**
1. **TLS Pass-through**: Proxy forwards TLS without termination
2. **Header Preservation**: Critical security headers preserved
3. **Certificate Validation**: Proper validation at each hop
4. **Audit Logging**: Comprehensive logging of all transactions

## 9. SNI and HTTP/2 Virtual Hosting

### 9.1 SNI (Server Name Indication)
SNI extension in TLS ClientHello specifies requested hostname:
```
ClientHello
  - extension: server_name(0)
  - server_name: "www.example.com"
```

### 9.2 HTTP/2 Virtual Hosting Challenges

**Certificate Selection:**
- Server must select correct certificate based on SNI
- Wildcard certificates simplify but have security implications
- Multi-domain certificates (SAN) required for connection coalescing

**Protocol Selection:**
- Different virtual hosts may support different HTTP versions
- ALPN negotiation must consider SNI
- Fallback mechanisms required

### 9.3 Security Considerations

**SNI Encryption**: ESNI (Encrypted SNI) and ECH (Encrypted Client Hello) protect SNI
**Certificate Validation**: Must validate against SNI hostname
**Virtual Host Isolation**: Proper isolation of security contexts

## 10. Forward Secrecy Requirements in HTTP/2

### 10.1 Forward Secrecy Definition
Forward secrecy ensures that compromise of long-term private keys doesn't compromise past session keys.

### 10.2 HTTP/2 Forward Secrecy Mandate
RFC 7540 strongly recommends forward secrecy:

**Required for:**
- All HTTP/2 implementations over TLS
- Both client and server implementations

**Achieved through:**
- Ephemeral key exchange (ECDHE, DHE)
- Not static RSA key exchange

### 10.3 Implementation Requirements

**Cipher Suite Selection:**
```
Mandatory: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
Recommended: TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
```

**Key Exchange Parameters:**
- Minimum 2048-bit DH parameters
- P-256 elliptic curve for ECDHE
- Regular key rotation

### 10.4 Security Benefits

**Compromise Resilience**: Past communications remain secure
**Key Rotation**: Regular key updates without reissuing certificates
**Perfect Forward Secrecy (PFS)**: Each session uses unique ephemeral keys

## 11. Specific Attack Vectors and Countermeasures

### 11.1 HPACK Compression Oracle Attacks

**Attack Description:**
HPACK's dynamic table compression can leak information through compression ratio side channels.

**Specific Attacks:**
1. **CRIME (Compression Ratio Info-leak Made Easy)**: 
   - Exploits DEFLATE compression in TLS
   - HTTP/2 uses HPACK which is vulnerable to similar attacks

2. **BREACH (Browser Reconnaissance and Exfiltration via Adaptive Compression of Hypertext)**:
   - Targets HTTP response compression
   - Can extract CSRF tokens, session IDs from responses

3. **TIME (Timing Info-leak Made Easy)**:
   - Measures compression time variations
   - Infers secret values based on processing time

**Countermeasures:**
```nginx
# Nginx configuration for HPACK protection
http2_max_field_size 4k;
http2_max_header_size 16k;
http2_body_preread_size 64k;

# Disable compression for sensitive responses
gzip off;
```

```go
// Go implementation with HPACK protection
type SecureHPACKDecoder struct {
    *hpack.Decoder
    maxTableSize uint32
    sensitiveHeaders map[string]bool
}

func (d *SecureHPACKDecoder) decodeHeader(f *frames.HeadersFrame) {
    // Never index sensitive headers
    for _, h := range f.HeaderFields {
        if d.sensitiveHeaders[strings.ToLower(h.Name)] {
            h.Sensitive = true  // Mark as never index
        }
    }
    d.Decode(f)
}
```

### 11.2 Stream Dependency Attacks

**Attack Description:**
Attackers can manipulate stream dependencies to cause denial of service or priority inversion.

**Attack Scenarios:**
1. **Circular Dependency Creation**:
   ```
   Stream 3 depends on Stream 5
   Stream 5 depends on Stream 3
   → Deadlock in stream scheduling
   ```

2. **Priority Exhaustion**:
   ```
   Create thousands of streams with MAX priority
   Exhaust server resources
   ```

3. **Dependency Tree Manipulation**:
   ```
   Malicious: Stream 100 depends on Stream 1 (critical)
   Legitimate: Stream 101 depends on Stream 100
   → Attacker controls scheduling of legitimate stream
   ```

**Countermeasures:**
```python
class SecureStreamManager:
    def __init__(self):
        self.max_streams = 100
        self.dependency_depth_limit = 10
        self.circular_dep_check = set()
    
    def validate_priority(self, stream_id, depends_on, weight):
        # Prevent circular dependencies
        if self._has_circular_dependency(stream_id, depends_on):
            raise ProtocolError("Circular dependency detected")
        
        # Limit dependency depth
        depth = self._get_dependency_depth(depends_on)
        if depth > self.dependency_depth_limit:
            raise ProtocolError("Dependency depth exceeded")
        
        # Validate weight
        if not (1 <= weight <= 256):
            raise ProtocolError("Invalid priority weight")
```

### 11.3 Flow Control Attacks

**Attack Description:**
Manipulating WINDOW_UPDATE frames to cause resource exhaustion or starvation.

**Attack Vectors:**
1. **Window Size Inflation**:
   ```
   Send WINDOW_UPDATE with very large increment
   Cause memory exhaustion on receiver
   ```

2. **Window Size Deflation**:
   ```
   Send WINDOW_UPDATE with negative increment (if allowed)
   Or don't send WINDOW_UPDATE at all
   Cause sender to block indefinitely
   ```

3. **Stream vs Connection Window Confusion**:
   ```
   Manipulate connection-level window to affect all streams
   ```

**Countermeasures:**
```c
// C implementation with flow control limits
#define MAX_WINDOW_SIZE (1 << 30)  // 1GB
#define MIN_WINDOW_SIZE 65535      // Initial window

int process_window_update(http2_session *s, uint32_t stream_id, 
                          uint32_t window_increment) {
    // Validate window increment
    if (window_increment == 0) {
        return PROTOCOL_ERROR;
    }
    
    // Prevent window size overflow
    uint32_t current_window = get_current_window(s, stream_id);
    if (current_window > MAX_WINDOW_SIZE - window_increment) {
        return FLOW_CONTROL_ERROR;
    }
    
    // Apply increment
    return update_window(s, stream_id, window_increment);
}
```

### 11.4 Frame Padding Attacks

**Attack Description:**
HTTP/2 frames can include padding, which can be abused for various attacks.

**Attack Scenarios:**
1. **Resource Exhaustion**:
   ```
   Send DATA frames with maximum padding
   Waste bandwidth and processing resources
   ```

2. **Timing Analysis**:
   ```
   Use padding to create distinguishable timing patterns
   Leak information about processing
   ```

3. **Evasion Techniques**:
   ```
   Pad malicious frames to avoid detection
   ```

**Countermeasures:**
```java
public class SecureFrameParser {
    private static final int MAX_PADDING = 256;
    private static final int MAX_CONSECUTIVE_PADDED_FRAMES = 10;
    
    public Frame parseFrame(ByteBuffer buffer) throws ProtocolException {
        Frame frame = decodeFrame(buffer);
        
        // Validate padding
        if (frame.hasPadding() && frame.paddingLength() > MAX_PADDING) {
            throw new ProtocolException("Excessive padding");
        }
        
        // Track padded frames for rate limiting
        if (frame.hasPadding()) {
            paddedFrameCount++;
            if (paddedFrameCount > MAX_CONSECUTIVE_PADDED_FRAMES) {
                throw new ProtocolException("Too many padded frames");
            }
        } else {
            paddedFrameCount = 0;
        }
        
        return frame;
    }
}
```

### 11.5 Continuation Frame Attacks

**Attack Description:**
CONTINUATION frames can be abused to create excessively large header blocks.

**Attack Vectors:**
1. **Header Block Fragmentation**:
   ```
   Split single header into thousands of CONTINUATION frames
   Cause memory exhaustion during reassembly
   ```

2. **Interleaving Attacks**:
   ```
   Interleave CONTINUATION frames from different streams
   Confuse header block reassembly
   ```

3. **Endless CONTINUATION**:
   ```
   Never send END_HEADERS flag
   Keep connection in pending state indefinitely
   ```

**Countermeasures:**
```rust
// Rust implementation with CONTINUATION protection
struct SecureHeaderReassembler {
    max_header_block_size: usize,
    max_continuation_frames: usize,
    current_block: Vec<u8>,
    continuation_count: usize,
}

impl SecureHeaderReassembler {
    fn process_continuation(&mut self, frame: ContinuationFrame) -> Result<(), Error> {
        // Limit number of CONTINUATION frames
        self.continuation_count += 1;
        if self.continuation_count > self.max_continuation_frames {
            return Err(Error::TooManyContinuations);
        }
        
        // Limit total header block size
        if self.current_block.len() + frame.block_fragment.len() > self.max_header_block_size {
            return Err(Error::HeaderBlockTooLarge);
        }
        
        self.current_block.extend_from_slice(&frame.block_fragment);
        
        if frame.flags.contains(Flags::END_HEADERS) {
            // Process complete header block
            self.reset();
        }
        
        Ok(())
    }
}
```

## 12. Implementation Security Checklist

### 12.1 TLS Configuration
- [ ] TLS 1.2 or higher required
- [ ] Forward secrecy cipher suites only
- [ ] ALPN extension properly implemented
- [ ] Certificate validation enabled
- [ ] SNI support implemented
- [ ] OCSP stapling enabled
- [ ] HSTS headers configured

### 12.2 HTTP/2 Protocol Security
- [ ] HPACK sensitive header protection
- [ ] Stream dependency validation
- [ ] Flow control limits enforced
- [ ] Frame size limits configured
- [ ] Padding validation implemented
- [ ] CONTINUATION frame limits
- [ ] Priority validation

### 12.3 Network Security
- [ ] Rate limiting per connection
- [ ] Rate limiting per IP
- [ ] Connection timeout configuration
- [ ] Maximum concurrent streams limit
- [ ] Header size limits
- [ ] Frame size limits

### 12.4 Monitoring and Logging
- [ ] Protocol downgrade detection
- [ ] Excessive padding detection
- [ ] Circular dependency detection
- [ ] Flow control abuse detection
- [ ] Header compression attacks detection
- [ ] All security events logged

## Conclusion

HTTP/2's security model represents a significant advancement over HTTP/1.1, with mandatory TLS in practice, strict cipher suite requirements, and enhanced protection mechanisms. The protocol's design addresses modern security threats while maintaining compatibility with existing infrastructure.

**Key Security Takeaways:**
1. **TLS is effectively mandatory** for HTTP/2 in browser contexts
2. **Cipher suite restrictions** eliminate weak cryptography
3. **Forward secrecy is required** for all connections
4. **ALPN provides secure protocol negotiation**
5. **Connection coalescing requires careful certificate management**
6. **Intermediaries introduce complex security considerations**
7. **HPACK requires specific protections** against compression oracle attacks
8. **Stream management needs validation** to prevent dependency attacks
9. **Flow control must be carefully implemented** to prevent resource exhaustion
10. **Frame validation is critical** for all frame types

**Emerging Threats and Future Directions:**
- **QUIC and HTTP/3**: New transport protocol with built-in security
- **Post-Quantum Cryptography**: Preparing for quantum computing threats
- **Encrypted Client Hello**: Protecting SNI from surveillance
- **Oblivious HTTP**: Enhancing privacy through proxy layers

The HTTP/2 security model continues to evolve with TLS 1.3 adoption, providing even stronger security guarantees while maintaining the performance benefits that motivated HTTP/2's development. Implementations must remain vigilant against both known attacks and emerging threats, with continuous security testing and protocol updates.