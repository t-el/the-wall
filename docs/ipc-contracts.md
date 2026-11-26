# IPC Contracts: Rust Data Plane ↔ Go Control Plane

## Communication
- Primary: NATS (thewall.remediation subject)
- Fallback: gRPC over mTLS

## Remediation Event Schema
Published by data plane on threat detection.

```json
{
  "action": "contain",
  "source": "dataplane",
  "marker_hit": true,
  "playbooks": ["dgssi_screenconnect_rmm"],
  "event": { },
  "timestamp": "rfc3339",
  "severity": "high",
  "requires_macert": true,
  "tenant_id": "string",
  "asset_class": "A|B|C"
}
```
