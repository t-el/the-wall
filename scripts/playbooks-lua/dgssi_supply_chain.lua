-- Production: Supply-chain and unsigned binary execution
-- Relevant for MSP / ScreenConnect compromise chains

function evaluate_threat(event)
    local path = (event.file_path or ""):lower()
    local unsigned = event.signed == false or event.signature_valid == false

    if unsigned and (string.find(path, "\\temp\\") or string.find(path, "\\downloads\\") or string.find(path, "/tmp/") or string.find(path, "appdata")) then
        log_warn("Unsigned binary executed from temporary path")
        return true
    end

    local supply_chain = {
        "sckit", "rmm+", "labtech", "screenconnect client"
    }
    local process = (event.process_name or ""):lower()
    local filename = (event.file_name or ""):lower()

    for _, ind in ipairs(supply_chain) do
        if string.find(process, ind) or string.find(filename, ind) then
            if unsigned or event.is_new_file then
                log_warn("Possible supply-chain / unauthorized RMM binary: " .. ind)
                return true
            end
        end
    end

    return false
end

function remediate(event)
    log_warn("Supply-chain containment: quarantine binary, revoke tokens, notify MSP owner")
end
