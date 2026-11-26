# Production DGSSI Playbooks

All scripts are loaded automatically by the data plane at startup from:
- `$PLAYBOOKS_DIR` (default `/etc/the-wall/playbooks`)
- or `../../scripts/playbooks-lua` as container/local fallback

Each playbook is isolated in its own Lua state.

## Interface
```lua
function evaluate_threat(event)
    -- return true on match
end

function remediate(event)
    -- containment actions
end
```

## Loaded playbooks
- dgssi_screenconnect_rmm.lua
- dgssi_unauthorized_rmm.lua
- dgssi_lateral_movement.lua
- dgssi_credential_access.lua
- dgssi_data_exfiltration.lua
- dgssi_dnssi_classification.lua
- dgssi_macert_escalation.lua
- dgssi_phishing_domains.lua
- dgssi_ransomware.lua
- dgssi_persistence.lua
- dgssi_webshell.lua
- dgssi_dns_tunneling.lua
- dgssi_supply_chain.lua
- block_malicious_ip.lua
- isolate_endpoint.lua
- dnssi_classify_asset.lua

Markers can be extended at runtime via the `DGSSI_MARKERS` environment variable.
