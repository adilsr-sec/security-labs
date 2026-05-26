# Multi-Threaded Network Port Scanner

A lightweight Python command-line utility for scanning target systems for open TCP ports and identifying active services via banner grabbing.

---

## 🎯 Project Objective

Active reconnaissance is one of the initial stages of any security assessment. This project was developed to:
1. Understand the mechanics of TCP connections and the **3-way handshake** at the socket layer.
2. Implement **concurrency** in Python to perform quick network scanning without blocking.
3. Incorporate safety features like target IP validation and bounds-checking to demonstrate **defensive coding**.

---

## ⚙️ How it Works

The scanner operates using a simple **TCP Connect Scan** strategy:
1. **Target Verification:** Resolves DNS hostname targets to IPv4/IPv6 addresses, verifying standard formats using Python's native `ipaddress` library.
2. **TCP Connection Request:** Spawns socket connections using `socket.connect_ex()`, which returns `0` if the connection completes successfully (indicating an open port), or an error code if closed/filtered.
3. **Multi-Threading:** Distributes the target port range across a thread pool using Python's `concurrent.futures.ThreadPoolExecutor` to speed up the process.
4. **Service Banner Identification:** If a connection is successfully made on a port, the scanner immediately sends a short probe and listens for any incoming data (e.g., standard protocol headers) to extract the service banner.

---

## 🛠️ Usage Instructions

### Prerequisites
Make sure Python 3.6+ is installed. No third-party modules are required for basic usage as the script only uses standard libraries.

### Command-Line Arguments
```bash
python scanner.py [TARGET] [OPTIONS]
```

* **`TARGET`**: Hostname or IP address to scan (e.g., `127.0.0.1` or `localhost`).
* **`-p` or `--ports`**: Range or comma-separated list of ports to scan. E.g., `22-80` or `80,443,8080`. (If omitted, the scanner defaults to scanning a list of common system ports).
* **`-t` or `--threads`**: Number of threads (default: 10).

### Execution Example
To scan ports 20 through 100 on `localhost` with 15 threads:
```bash
python scanner.py localhost -p 20-100 -t 15
```

---

## 📊 Sample Terminal Output

```text
[*] Initializing scan on target: localhost
[*] Target resolved to IP: 127.0.0.1
[*] Scanning 81 ports using 15 threads...

PORT    STATUS    SERVICE           BANNER/INFO
------------------------------------------------------------
22      Open      SSH               SSH-2.0-OpenSSH_8.9p1 Ubuntu-3
80      Open      HTTP              HTTP/1.1 200 OK ...
53      Open      DNS               N/A

[*] Scan completed.
```

---

## 🛡️ Security & Defensive Coding Features

* **Error Isolation:** Handles socket timeouts, ConnectionRefused, and HostUnreachable exceptions gracefully to ensure the scanner doesn't crash mid-scan.
* **Domain Check:** Employs domain syntax verification to protect against invalid target parameters.
* **Controlled Scope:** Banner grabbing requests are time-capped at 1.5 seconds to prevent hung connections or socket starvation issues.
