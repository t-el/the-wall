# The Wall (Le Mur Numérique)

Production-grade cybersecurity platform for Moroccan Public Administrations and IIV.

## Compliance
- Loi 05-20 / Dahir 1-20-69
- DNSSI (11 domains, Classes A/B/C)
- Décret 2-24-921 & Arrêté 3-17-25 (Level 2 Sovereign Cloud)
- Law 09-08 (CNDP)

## Architecture
- **Rust**: Data plane, crypto, Lua sandbox, zero-copy ingestion
- **Go**: Control plane, GRC, maCERT dispatcher, APIs
- **Lua**: Hot-swappable playbooks

## Modules Status
- **Module 1** (dataplane-rust): Production — auto-loads all playbooks (isolated Lua states), TCP/UDP ingestion, publishes structured remediation events to NATS
- **Module 2** (crypto-rust): Implemented — Level 2 client-exclusive key handles, zeroize, export forbidden
- **Module 3** (controlplane-go): Production — NATS subscriber, append-only hash-chained logs (Art. 26), DNSSI audit evidence
- **Module 4** (macert-exporter-go): Production — NATS subscriber, auto-dispatches when requires_macert=true (Art. 8/30/33)
- **Module 5** (playbooks-lua): 16 production DGSSI-aligned playbooks

## Live stack
```bash
docker compose -f deployments/docker-compose.yml up --build
```
Data plane publishes to `thewall.remediation`. Control plane and maCERT exporter both subscribe.

## Quick Start
```bash
make run-dataplane
cargo build --release --workspace
```
