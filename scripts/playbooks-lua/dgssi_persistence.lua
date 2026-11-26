-- Production: Persistence and scheduled task abuse
-- Common post-exploitation on Moroccan public systems

function evaluate_threat(event)
    local persistence = {
        "schtasks /create", "reg add hklm\\software\\microsoft\\windows\\currentversion\\run",
        "reg add hkcu\\software\\microsoft\\windows\\currentversion\\run",
        "wmic startup", "bitsadmin /transfer",
        "/sc create", "new-scheduledtask", "crontab"
    }

    local cmdline = (event.cmdline or ""):lower()
    local event_type = (event.event_type or ""):lower()

    for _, p in ipairs(persistence) do
        if string.find(cmdline, p) or string.find(event_type, p) then
            log_warn("Persistence mechanism detected: " .. p)
            return true
        end
    end

    if event.service_path and (string.find(event.service_path:lower(), "\\temp\\") or string.find(event.service_path:lower(), "\\appdata\\")) then
        log_warn("Service installed from suspicious path")
        return true
    end

    return false
end

function remediate(event)
    log_warn("Persistence containment: remove scheduled task / run key, isolate host")
end
