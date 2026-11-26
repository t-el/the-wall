-- Production: Ransomware and destructive malware indicators
-- Aligned with DGSSI / maCERT destructive code alerts

function evaluate_threat(event)
    local indicators = {
        "vssadmin delete shadows", "wbadmin delete catalog",
        "bcdedit /set {default} recoveryenabled no",
        "cipher /w:", "wevtutil cl", "fsutil usn deletejournal",
        ".encrypted", ".locked", ".crypt", "readme.txt",
        "how_to_decrypt", "your files have been"
    }

    local cmdline = (event.cmdline or ""):lower()
    local filename = (event.file_name or ""):lower()
    local process = (event.process_name or ""):lower()

    for _, ind in ipairs(indicators) do
        if string.find(cmdline, ind) or string.find(filename, ind) or string.find(process, ind) then
            log_warn("Ransomware / destructive indicator: " .. ind)
            return true
        end
    end

    if event.files_modified and event.files_modified > 100 and event.window_seconds and event.window_seconds < 60 then
        log_warn("Mass file encryption pattern detected")
        return true
    end

    return false
end

function remediate(event)
    log_warn("Ransomware containment: isolate host, disable network, preserve memory dump")
end
