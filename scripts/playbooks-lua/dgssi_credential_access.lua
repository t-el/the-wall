-- DGSSI-aligned credential access and privilege escalation

function evaluate_threat(event)
    local cred_indicators = {
        "mimikatz", "procdump", "lsass", "sekurlsa",
        "ntdsutil", "vssadmin create shadow", "reg save hklm\\sam",
        "reg save hklm\\security", "comsvcs.dll"
    }

    local cmdline = (event.cmdline or ""):lower()
    local process = (event.process_name or ""):lower()

    for _, ind in ipairs(cred_indicators) do
        if string.find(cmdline, ind) or string.find(process, ind) then
            log_info("Credential access / dumping indicator: " .. ind)
            return true
        end
    end

    if event.integrity_level == "high" and event.parent_integrity == "medium" then
        log_info("Privilege escalation detected")
        return true
    end

    return false
end

function remediate(event)
    log_info("DGSSI: revoke credentials, force password reset, isolate endpoint")
end
