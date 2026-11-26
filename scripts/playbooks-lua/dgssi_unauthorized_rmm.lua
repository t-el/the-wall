-- DGSSI-aligned: Suspicious remote access and unauthorized RMM clients

function evaluate_threat(event)
    local suspicious_tools = {
        "anydesk", "teamviewer", "ultraviewer", "supremo",
        "rustdesk", "ammyy", "logmein", "splashtop",
        "scscreenconnect", "screenconnect", "sckit"
    }

    local process = (event.process_name or ""):lower()
    local path = (event.file_path or ""):lower()

    for _, tool in ipairs(suspicious_tools) do
        if string.find(process, tool) or string.find(path, tool) then
            if event.is_new_process or event.parent_process == "explorer.exe" then
                log_info("Suspicious remote access tool: " .. tool)
                return true
            end
        end
    end

    return false
end

function remediate(event)
    log_info("DGSSI: terminate unauthorized remote session and quarantine binary")
end
