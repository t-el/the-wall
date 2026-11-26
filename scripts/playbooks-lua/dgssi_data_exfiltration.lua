-- DGSSI / DNSSI Class A/B: Data exfiltration and unusual outbound patterns

function evaluate_threat(event)
    if event.bytes_out and event.bytes_out > 100 * 1024 * 1024 then
        log_info("Large outbound transfer detected (" .. event.bytes_out .. " bytes)")
        return true
    end

    local suspicious_domains = {
        "pastebin.com", "mega.nz", "dropbox.com", "wetransfer.com",
        "anonfiles", "temp.sh", "transfer.sh"
    }
    local dst = (event.dst_domain or event.dst_ip or ""):lower()

    for _, dom in ipairs(suspicious_domains) do
        if string.find(dst, dom) then
            log_info("Possible exfiltration to file-sharing service: " .. dom)
            return true
        end
    end

    if event.dst_port and (event.dst_port == 4444 or event.dst_port == 8080 or event.dst_port == 53) then
        if event.bytes_out and event.bytes_out > 1024 * 1024 then
            log_info("Possible C2/exfil on suspicious port " .. event.dst_port)
            return true
        end
    end

    return false
end

function remediate(event)
    log_info("DGSSI: block outbound, capture PCAP, escalate Class A/B to maCERT")
end
