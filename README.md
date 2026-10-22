<img width="2172" height="724" alt="ischemia-horizontal-dissociated-refined" src="https://github.com/user-attachments/assets/85931b0a-520b-4834-afbc-9e83dbe77d54" />

# Ischemia

**Dissociated Security**

Ischemia is an HTTP/1.1 partial-entity hold testing tool. It exploits synchronous, thread-per-request server architectures by allocating worker threads and holding them in a blocked state, starving the backend of processing capacity.

It is designed for authorized penetration testing and infrastructure validation. It prioritizes evidentiary integrity, deterministic timing, and clean execution over raw noise.

>
> **Warning:** Ischemia is a denial-of-service testing tool. It is designed to exhaust server resources. Use only against targets you own or have explicit written authorization to test. The authors assume no liability for misuse.
>
>
 
## Mechanics

Ischemia executes a final-byte hold (partial-entity hold) attack:

1. **Arming:** Establishes concurrent TCP/TLS connections and transmits the HTTP headers and the request body minus the final byte.
2. **Holding:** The backend application server parses the `Content-Length` header, allocates a worker thread, and blocks on a `read()` syscall waiting for the remainder of the payload. Ischemia holds the connection open for a specified duration (`--hold-seconds`).
3. **Release:** The final byte is released simultaneously across all armed connections. 
4. **Measurement:** The tool captures precise timing metrics (armed, held, released, responded) to measure backend recovery time and generate evidence of resource exhaustion.


## Prerequisites

- Python 3.11+
- Linux/macOS
- Elevated file descriptor limits for high-concurrency runs.

```bash
# macOS
sudo launchctl limit maxfiles 65535 65535 && ulimit -n 65535

# Linux
ulimit -n 65535
```

## Usage
Basic concurrency control run (no hold):

```bash
python3 ischemia.py --host 127.0.0.1 --port 8080 --endpoint /api/login --connections 500 --hold-seconds 0 --out baseline-run
```

Standard partial-entity hold:
```bash
python3 ischemia.py --host 127.0.0.1 --port 8080 --endpoint /api/login --connections 2000 --arm-concurrency 256 --arm-rate 500 --hold-seconds 60 --data 'username=admin&password=pass' --out evidence-run-01
```

HTTPS with custom headers and raw sample capture:

```bash
python3 ischemia.py --scheme https --host target.com --port 443 --endpoint /submit --connections 1000 --hold-seconds 30 --header "X-Forwarded-For: 127.0.0.1" --raw-sample 5 --out tls-evidence
```

### Mitigation
To defend against partial-entity holds:

Enforce strict client_body_timeout limits at the reverse proxy or WAF level.
Configure reverse proxies (Nginx, HAProxy, ALB) to buffer the entire request body in memory/disk before forwarding it to the backend application server.
Migrate synchronous, thread-per-request application servers to asynchronous, event-driven I/O models where idle connections do not consume dedicated worker threads.

Author: D3N14LD15K | Dissociated Security
