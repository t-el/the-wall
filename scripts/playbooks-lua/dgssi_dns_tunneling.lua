-- Production: DNS tunneling and unusual DNS patterns
-- Common C2 technique against monitored networks

function evaluate_threat(event)
    if event.protocol ~= "dns" and event.dst_port ~= 53 then
        return false
    end

    local qname = (event.dns_query or event.dst_domain or ""):lower()

    if #qname > 80 then
        log_warn("Excessively long DNS query (possible tunneling): " .. #qname .. " chars")
        return true
    end

    local subdomain = qname:match("^([^.]+)%." )
    if subdomain and #subdomain > 40 then
        local has_mixed = subdomain:match("[a-z]") and subdomain:match("[A-Z]") and subdomain:match("%d")
        if has_mixed then
            log_warn("High-entropy DNS subdomain (possible tunneling)")
            return true
        end
    end

    if event.dns_query_count and event.dns_query_count > 500 and event.window_seconds and event.window_seconds < 60 then
        log_warn("High DNS query volume")
        return true
    end

    return false
end

function remediate(event)
    log_warn("DNS tunneling containment: sinkhole domain, isolate host")
end
