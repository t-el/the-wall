# The Wall (Le Mur Numérique)

Production-grade cybersecurity platform for Moroccan Public Administrations and IIV.

## Compliance
- Loi 05-20 / Dahir 1-20-69
- DNSSI (11 domains, Classes A/B/C)
- Décret 2-24-921 & Arrêté 3-17-25 (Level 2 Sovereign Cloud)
- Law 09-08 (CNDP)

## Architecture
- **Go**: Data plane, control plane, maCERT dispatcher, APIs
- **Lua**: Hot-swappable DGSSI playbooks (gopher-lua)

## Modules
- **dataplane-go**: TCP/UDP ingestion, isolated Lua playbooks, NATS remediation
- **controlplane-go**: Persistent hash-chained audit log (TimescaleDB)
- **macert-exporter-go**: Conditional maCERT alert dispatch
- **playbooks-lua**: DGSSI-aligned detection rules

## Live stack
```bash
docker compose -f deployments/docker-compose.yml up --build
```

## Quick start
```bash
make run-dataplane
```
