//! Production network & log ingestion
//! TCP 5140 + UDP 514, JSON events, multi-playbook evaluation, NATS publish

use crate::{lua_engine::LuaEngine, marker_evaluator::DgssiMarkerEvaluator};
use anyhow::Result;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, UdpSocket};
use tracing::{info, warn, error};

pub struct IngestionContext {
    pub lua: Arc<LuaEngine>,
    pub evaluator: Arc<DgssiMarkerEvaluator>,
    pub nats: async_nats::Client,
}

pub async fn start_tcp_listener(ctx: Arc<IngestionContext>) -> Result<()> {
    let listener = TcpListener::bind("0.0.0.0:5140").await?;
    info!("TCP ingestion listening on 0.0.0.0:5140");

    loop {
        let (mut socket, addr) = listener.accept().await?;
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            loop {
                match socket.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Ok(s) = std::str::from_utf8(&buf[..n]) {
                            for line in s.lines() {
                                let line = line.trim();
                                if line.is_empty() { continue; }
                                if let Ok(event) = serde_json::from_str::<serde_json::Value>(line) {
                                    process_event(&event, &ctx).await;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!(addr = %addr, error = %e, "TCP read error");
                        break;
                    }
                }
            }
        });
    }
}

pub async fn start_udp_listener(ctx: Arc<IngestionContext>) -> Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:514").await?;
    info!("UDP ingestion listening on 0.0.0.0:514");

    let mut buf = [0u8; 8192];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((n, _addr)) => {
                if let Ok(s) = std::str::from_utf8(&buf[..n]) {
                    let s = s.trim();
                    if let Ok(event) = serde_json::from_str::<serde_json::Value>(s) {
                        process_event(&event, &ctx).await;
                    }
                }
            }
            Err(e) => error!(error = %e, "UDP recv error"),
        }
    }
}

async fn process_event(event: &serde_json::Value, ctx: &IngestionContext) {
    let marker_hit = ctx.evaluator.evaluate(event);
    let playbook_hits = ctx.lua.evaluate_all(event);

    if marker_hit || !playbook_hits.is_empty() {
        warn!(
            event = %event,
            marker_hit,
            playbooks = ?playbook_hits,
            "THREAT DETECTED — DGSSI markers / playbooks matched"
        );

        let remediation = serde_json::json!({
            "action": "contain",
            "source": "dataplane",
            "marker_hit": marker_hit,
            "playbooks": playbook_hits,
            "event": event,
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "severity": if marker_hit { "high" } else { "medium" },
            "requires_macert": event.get("asset_class").and_then(|v| v.as_str()) == Some("A")
                || marker_hit,
            "tenant_id": event.get("tenant_id").and_then(|v| v.as_str()).unwrap_or("default"),
            "asset_class": event.get("asset_class").and_then(|v| v.as_str()).unwrap_or("B")
        });

        let payload = remediation.to_string();
        if let Err(e) = ctx.nats.publish("thewall.remediation", payload.into()).await {
            error!(error = %e, "Failed to publish remediation event to NATS");
        } else {
            info!("Remediation event published to NATS (thewall.remediation)");
        }
    }
}
