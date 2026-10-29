# Isolated Docker Practice Lab

This laboratory provides an isolated, multi-container private bridge network (`172.28.0.0/16`) for safe port scanning, service enumeration, and banner grabbing without touching production networks.

---

## Architecture Overview

| Container | Internal IP | Exposed Host Port | Service | Default Banner / Behavior |
| :--- | :--- | :--- | :--- | :--- |
| **nginx_target** | `172.28.0.10` | `8080` (HTTP) | Nginx Alpine Web Server | Emits `Server: nginx/...` on HTTP requests |
| **redis_target** | `172.28.0.20` | `6379` (TCP) | Redis In-Memory Datastore | Emits `-ERR unknown command` or redis info |
| **postgres_target** | `172.28.0.30` | `5432` (TCP) | PostgreSQL Database | Responds to SSL / standard startup packets |
| **ftp_target** | `172.28.0.40` | `2121` (TCP) | vsftpd File Transfer Protocol | Emits greeting `220 (vsFTPd ...)` upon connection |

---

## Instructions

### 1. Prerequisites
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (Windows/macOS) or Docker Engine + Docker Compose (Linux).

### 2. Start the Lab Environment
From the project root directory, execute:
```bash
docker compose -f lab/docker-compose.yml up -d
```

Verify all four containers are in an active running state:
```bash
docker compose -f lab/docker-compose.yml ps
```

### 3. Scanning the Lab from Host Machine

#### Scan the Host Mapped Ports:
```bash
python main.py -t 127.0.0.1 -p 2121,5432,6379,8080 --timeout 1.0
```

#### Scan the Container Network Directly (Linux / Docker Desktop Routing):
```bash
python main.py -t 172.28.0.0/24 -p 21,80,5432,6379 --timeout 1.0
```

### 4. Stop and Clean Up Lab
When finished testing, shut down the lab and tear down the virtual bridge network:
```bash
docker compose -f lab/docker-compose.yml down
```
