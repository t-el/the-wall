-- Production: Web shell and suspicious process trees
-- Targets common web-facing public administration systems

function evaluate_threat(event)
    local webshell_names = {
        "cmd.aspx", "shell.aspx", "c99.php", "r57.php",
        "wso.php", "b374k.php", "weevely", "china chopper"
    }

    local filename = (event.file_name or ""):lower()
    local path = (event.file_path or ""):lower()

    for _, name in ipairs(webshell_names) do
        if string.find(filename, name) or string.find(path, name) then
            log_warn("Web shell indicator: " .. name)
            return true
        end
    end

    local parent = (event.parent_process or ""):lower()
    local process = (event.process_name or ""):lower()
    local web_servers = { "w3wp.exe", "httpd", "nginx", "php-cgi", "java", "tomcat" }
    local shells = { "cmd.exe", "powershell.exe", "bash", "sh", "python" }

    local parent_is_web = false
    for _, ws in ipairs(web_servers) do
        if string.find(parent, ws) then parent_is_web = true break end
    end

    if parent_is_web then
        for _, sh in ipairs(shells) do
            if string.find(process, sh) then
                log_warn("Web server spawned shell: " .. parent .. " -> " .. process)
                return true
            end
        end
    end

    return false
end

function remediate(event)
    log_warn("Web shell containment: isolate host, quarantine file, block source IP")
end
