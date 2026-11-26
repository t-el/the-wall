//! Sovereign Data Plane - Module 1
//! Production ingestion + multi-playbook DGSSI evaluation + NATS remediation

use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, warn};

mod lua_engine;
mod marker_evaluator;
mod ingestion;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .json()
        .init();

    info!("Starting The Wall Sovereign Data Plane");

    let mut engine = lua_engine::LuaEngine::new();
    let playbooks_dir = std::env::var("PLAYBOOKS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/etc/the-wall/playbooks"));

    let playbooks_dir = if playbooks_dir.exists() {
        playbooks_dir
    } else {
        let fallback = PathBuf::from("../../scripts/playbooks-lua");
        if fallback.exists() {
            info!(path = %fallback.display(), "Using fallback playbooks directory");
            fallback
        } else {
            playbooks_dir
        }
    };

    let loaded = engine.load_directory(&playbooks_dir)?;
    if loaded == 0 {
        warn!("No playbooks loaded — detection will rely on marker evaluator only");
    }

    let nats_url = std::env::var("NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".into());
    let nats = async_nats::connect(&nats_url).await
        .map_err(|e| anyhow::anyhow!("NATS connect failed: {}", e))?;
    info!(url = %nats_url, "Connected to NATS");

    let ctx = Arc::new(ingestion::IngestionContext {
        lua: Arc::new(engine),
        evaluator: Arc::new(marker_evaluator::DgssiMarkerEvaluator::new()),
        nats,
    });

    let tcp = tokio::spawn(ingestion::start_tcp_listener(ctx.clone()));
    let udp = tokio::spawn(ingestion::start_udp_listener(ctx.clone()));

    info!("Data plane ready — TCP:5140 UDP:514  NATS remediation active");

    tokio::select! {
        r = tcp => warn!("TCP listener exited: {:?}", r),
        r = udp => warn!("UDP listener exited: {:?}", r),
    }

    Ok(())
}
