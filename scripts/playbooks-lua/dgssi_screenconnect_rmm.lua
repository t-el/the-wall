-- DGSSI Alert 71001211/26 — ScreenConnect / RMM+ / SCKit detection
-- Based on November 2026 critical bulletin targeting ConnectWise ScreenConnect
-- and managed service providers (MSP)

function evaluate_threat(event)
    local indicators = {
        "screenconnect", "scscreenconnect", "connectwise",
        "sckit", "rmm+", "labtech plus", "rmm plus",
        "run command", "shared toolbox"
    }

    local payload = (event.payload or ""):lower()
    local process = (event.process_name or ""):lower()
    local cmdline = (event.cmdline or ""):lower()

    for _, ind in ipairs(indicators) do
        if string.find(payload, ind) or string.find(process, ind) or string.find(cmdline, ind) then
            log_info("DGSSI ScreenConnect/RMM indicator matched: " .. ind)
            return true
        end
    end

    if event.command_count and event.command_count > 10 then
        log_info("Mass remote command execution detected (DGSSI ScreenConnect pattern)")
        return true
    end

    return false
end

function remediate(event)
    log_info("DGSSI playbook: isolate ScreenConnect/RMM session and revoke tokens")
end
