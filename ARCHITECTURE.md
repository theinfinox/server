# PiCloud Telemetry & Zero-Trust Security Architecture

This document details the security model, ingress controls, cryptographic gate, and dual-tier telemetry streaming pipeline powering the **PiCloud Server Metrics Dashboard** (`https://info.govindsr.me` / `wss://serverws.govindsr.me`).

---

## 1. System Overview & Dataflow Architecture

The dashboard implements a **Zero-Trust Dual-Tier Architecture**. Public visitors receive a sanitized, privacy-hardened telemetry stream that hides microarchitecture details, hardware network bindings, internal process identifiers, and crash feedback oracles. Privileged operators can unlock full, unmasked telemetry and motherboard-level sensors in real time via an authenticated WebSocket session.

```mermaid
flowchart TD
    subgraph Ingress["Layer 1: Ingress & Network Defense"]
        Client["Browser Client (Visitor or Admin)"] -->|WSS Handshake| CF["Cloudflare Tunnel (Edge Proxy)"]
        CF -->|HTTP Upgrade| WSS["Node.js WebSocket Server (Port 3000)"]
        WSS --> V1{"Origin Header Allowed?"}
        V1 -- No --> R1["Reject Handshake (403 Forbidden)"]
        V1 -- Yes --> V2{"Global Connections < 50?"}
        V2 -- No --> R2["Reject Handshake (503 Server Busy)"]
        V2 -- Yes --> V3{"IP Concurrent Sockets < 5?"}
        V3 -- No --> R3["Reject Handshake (429 Rate Limit)"]
        V3 -- Yes --> SocketOpen["Socket Established (State: Public Tier)"]
    end

    subgraph AuthGate["Layer 2: Zero-Trust Cryptographic Gate"]
        SocketOpen --> MsgType{"Incoming Frame Type"}
        
        MsgType -- "type: 'auth_token'" --> VerifyToken{"Token HMAC Valid & Age < 30d?"}
        VerifyToken -- Yes --> Elevate["Socket Elevated to Privileged Tier"]
        VerifyToken -- No --> TokenExpired["Send 'auth_token_expired' (Stay Public)"]
        
        MsgType -- "type: 'auth'" --> CheckLockout{"IP Locked Out? (>= 3 Fails)"}
        CheckLockout -- Yes --> SendLockout["Send 'auth_error' (30-Min Cooldown Active)"]
        CheckLockout -- No --> HashCheck{"HMAC-SHA256 Match? (crypto.timingSafeEqual)"}
        
        HashCheck -- Match --> ResetFails["Clear IP Fail Count"]
        ResetFails --> GenToken["Generate 30-Day HMAC Session Token"]
        GenToken --> Elevate
        
        HashCheck -- Mismatch --> IncFail["IP Fail Count + 1"]
        IncFail --> CheckThreshold{"Fail Count >= 3?"}
        CheckThreshold -- Yes --> SetLockout["Set 30-Min Lockout Timestamp on IP"]
        CheckThreshold -- No --> SendFail["Send 'auth_error' (X Attempts Remaining)"]
        
        MsgType -- "type: 'logout'" --> Demote["Socket Demoted to Public Tier"]
    end

    subgraph TelemetryEngine["Layer 3: Single-Tick Dual-Tier Engine (1s Interval)"]
        Tick["Timer Tick (1000ms)"] --> ReadRaw["Collect Raw OS / PM2 / Sysfs Telemetry"]
        
        ReadRaw --> BuildPublic["Build publicPayload:
        - CPU Model: 'x86_64 Multi-Core'
        - Interface: 'UPLINK'
        - Thermal: 'CPU_PKG'
        - PM2 IDs: null
        - PM2 Names: Half-Masked (bms******ram)
        - Restarts: null (Oracle blocked)"]
        
        ReadRaw --> BuildPriv["Build privilegedPayload:
        - CPU Model: Intel i3-6006U (Exact)
        - Interface: eno1 (Physical PCIe)
        - Thermal: Multi-zone ACPI Sensors
        - PM2 IDs: #0, #1, #12
        - PM2 Names: Unmasked Full Strings
        - Restarts: Exact Numbers + Alerts"]
        
        BuildPublic --> SerPublic["Serialize publicMsg (JSON String)"]
        BuildPriv --> SerPriv["Serialize privilegedMsg (JSON String)"]
        
        SerPublic --> Dispatch{"Is Socket Authenticated?"}
        SerPriv --> Dispatch
        
        Dispatch -- "No (Public)" --> SendPublic["ws.send(publicMsg)"]
        Dispatch -- "Yes (Privileged)" --> SendPriv["ws.send(privilegedMsg)"]
    end

    SendPublic --> ClientPublic["Client View: Clean, Masked & Safe"]
    SendPriv --> ClientPriv["Client View: Unmasked & Full Privileged Data"]
```

---

## 2. Authentication & Brute-Force Lockout Sequence

```mermaid
sequenceDiagram
    autonumber
    actor User as Operator / Browser
    participant WS as WebSocket Server
    participant Lockout as IP Rate-Limiter
    participant Crypto as Crypto Engine (.auth-lock.json)

    User->>WS: Connect WSS (Default: Public Tier)
    WS-->>User: Streams publicPayload (Masked)

    alt Cached Session Token Present (Auto-Login)
        User->>WS: {"type": "auth_token", "token": "..."}
        WS->>Crypto: Verify HMAC signature with SERVER_BOOT_SECRET
        alt Token Valid & Age < 30 Days
            Crypto-->>WS: Signature Matches
            WS-->>User: {"type": "auth_token_success"}
            Note over WS,User: Socket instantly elevated to Privileged Tier
        else Token Expired or Tampered
            Crypto-->>WS: Signature Invalid
            WS-->>User: {"type": "auth_token_expired"}
        end
    else Operator Submits Master Key
        User->>WS: {"type": "auth", "key": "picloud0471@#"}
        WS->>Lockout: Check IP attempt history
        alt IP in 30-min Lockout Period
            Lockout-->>WS: IP Locked
            WS-->>User: {"type": "auth_error", "locked": true, "remainingMin": 30}
        else IP is Cleared
            WS->>Crypto: Hash key with Salt (HMAC-SHA256)
            WS->>Crypto: crypto.timingSafeEqual(expectedBuf, candidateBuf)
            alt Key Matches
                Crypto-->>WS: Constant-Time Match Verified
                WS->>Lockout: Clear IP fail records
                WS->>Crypto: Generate signed session token
                WS-->>User: {"type": "auth_success", "token": "..."}
                Note over WS,User: Socket elevated. Next tick sends privilegedPayload
            else Key Mismatches
                Crypto-->>WS: Hash Mismatch
                WS->>Lockout: Increment fail counter for IP
                alt Failures == 3
                    Lockout-->>WS: Trigger 30-min Cooldown
                    WS-->>User: {"type": "auth_error", "locked": true, "remainingMin": 30}
                else Failures < 3
                    WS-->>User: {"type": "auth_error", "attemptsLeft": 2}
                end
            end
        end
    end

    alt Operator Logs Out
        User->>WS: {"type": "logout"}
        WS-->>User: Socket downgraded back to Public Tier
        Note over User: localStorage token purged
    end
```

---

## 3. Four Core Security Pillars

### Pillar 1: Ingress & Resource Exhaustion (DoS) Defense
1. **Origin Header Validation:** Executed inside Node's native `verifyClient` callback before WebSocket protocol upgrade. Unauthorized origins are rejected immediately with `403 Forbidden`.
2. **Per-IP Concurrency Limit:** Sockets per IP address (resolved via Cloudflare `cf-connecting-ip` / `x-forwarded-for`) are capped at `5` to prevent socket starvation.
3. **Global Concurrency Ceiling:** Capped at `50` simultaneous connections (`503 Service Unavailable`) to prevent host memory and file descriptor exhaustion.
4. **Strict Frame Size Cap:** Incoming WebSocket frames are clamped to `1024 bytes` (`maxPayload: 1024`). Any malformed buffer flooding attempt is dropped before JSON deserialization.

### Pillar 2: Cryptographic Gate & Zero Plaintext Footprint
1. **Salted HMAC-SHA256 Storage:** Plaintext keys are never stored on disk. `.auth-lock.json` stores a cryptographically generated 16-byte random salt and HMAC-SHA256 digest. If a plaintext key is ever provided in the file, it is automatically hashed and wiped from disk on boot.
2. **Timing-Attack Immunity (`crypto.timingSafeEqual`):** Comparisons between client candidate hashes and stored digests are executed in strict constant time, completely preventing microsecond side-channel analysis from deriving characters.
3. **3-Strike Hard Lockout:** Three consecutive failed authentication attempts from any IP enforce a 30-minute hard cooldown. Expired lockout records are automatically purged via background garbage collection.

### Pillar 3: Dual-Tier Telemetry Isolation
- The broadcast engine reads host telemetry **once per second** ($O(1)$ CPU overhead).
- It constructs **two distinct payload trees** (`publicPayload` and `privilegedPayload`) and serializes each once.
- Sensitive telemetry is filtered on the server before transmission; public clients never receive sensitive fields:
  - **CPU Model:** Masked to `x86_64 Multi-Core Processor` (preventing Skylake CVE microarchitecture fingerprinting).
  - **NIC Identifier:** Masked to `[UPLINK]` (hiding onboard PCIe `eno1` bus bindings).
  - **PM2 Service Names:** The middle ~50% of each service name is replaced with asterisks (e.g., `bms******ram`, `Sma*****lth`) to prevent service discovery.
  - **PM2 Instance IDs & Restarts:** Stripped from public payloads to eliminate the real-time crash-confirmation oracle during automated fuzzing or DoS attacks.
  - **Console Logs (stdout/stderr):** Completely gated to privileged sockets.

### Pillar 4: Friction-Free 30-Day Session Persistence
- Upon authentication, the server signs a cryptographically verifiable token (`timestamp.nonce.signature`) using a machine-local boot secret.
- The browser caches this token in `localStorage`.
- When an operator returns or refreshes within 30 days, the token automatically restores privileged access during the initial handshake without prompting for the password again.

---

## 4. Telemetry Masking Matrix

| Telemetry Field | Public Tier (Unauthenticated) | Privileged Tier (Authenticated) | Risk Mitigated |
| :--- | :--- | :--- | :--- |
| **CPU Model** | `x86_64 Multi-Core Processor` | `Intel(R) Core(TM) i3-6006U CPU @ 2.00GHz` | Prevents targeted speculative execution CVE exploits (Spectre, Meltdown, MDS). |
| **Network Interface** | `[UPLINK]` | `[ENO1]` | Conceals hardware PCIe network topology and physical bus indices. |
| **PM2 Process Name** | Middle 50% asterisks (`bms******ram`) | Full Unmasked Name (`bms-telegram`) | Prevents automated service discovery and OSINT mapping. |
| **PM2 Instance ID** | `🔒` (`null`) | Exact PM2 ID (`#12`, `#4`, etc.) | Hides internal orchestration order and worker IDs. |
| **PM2 Restarts** | `🔒` (`null`) | Real restart counts + excessive alerts | Eliminates real-time crash confirmation oracle for fuzzers. |
| **Motherboard Sensors** | Package temp only (`CPU_PKG`) | Full ACPI sensor tree (`x86_pkg_temp`, `acpitz`) | Conceals motherboard hardware revision and thermal bus paths. |
| **Application Logs** | Restricted (`🔒 [LOCKED]`) | Live stdout / stderr stream | Prevents IP, stack trace, and internal credential leakage. |
