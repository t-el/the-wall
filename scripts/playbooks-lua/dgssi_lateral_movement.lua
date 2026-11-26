-- DGSSI / DNSSI: Mass command execution and lateral movement indicators

function evaluate_threat(event)
    if event.event_type == "remote_command" and event.count and event.count >= 5 then
        log_info("Mass remote command execution (possible DGSSI RMM abuse)")
        return true
    end

    local lateral_indicators = {
        "psexec", "wmic", "schtasks /create", "net use",
        "smbexec", "wmiexec", "atexec"
    }
    local cmdline = (event.cmdline or ""):lower()

    for _, ind in ipairs(lateral_indicators) do
        if string.find(cmdline, ind) then
            log_info("Lateral movement indicator: " .. ind)
            return true
        end
    end

    return false
end

function remediate(event)
    log_info("DGSSI: restrict Run Command / Shared Toolbox, isolate source host")
end
