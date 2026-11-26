//! Production Lua engine for DGSSI playbooks
//! - One isolated Lua state per playbook (fault isolation)
//! - Auto-load all *.lua from directory
//! - Structured remediation events for control plane / maCERT
//! - Zero panics on script errors

use mlua::Lua;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use anyhow::{Context, Result};
use tracing::{info, warn, error};
use serde_json::Value;

pub struct Playbook {
    name: String,
    lua: Mutex<Lua>,
}

impl Playbook {
    fn new(name: &str, source: &str) -> Result<Self> {
        let lua = Lua::new();
        {
            let globals = lua.globals();
            globals.set("log_info", lua.create_function(|_, msg: String| {
                tracing::info!(target: "lua", playbook = name, "{}", msg);
                Ok(())
            })?)?;
            globals.set("log_warn", lua.create_function(|_, msg: String| {
                tracing::warn!(target: "lua", playbook = name, "{}", msg);
                Ok(())
            })?)?;
        }
        lua.load(source).set_name(name).exec()
            .with_context(|| format!("Failed to load playbook '{}'", name))?;

        Ok(Self {
            name: name.to_string(),
            lua: Mutex::new(lua),
        })
    }

    fn evaluate(&self, event: &Value) -> Result<bool> {
        let lua = self.lua.lock().unwrap();
        let func: mlua::Function = lua.globals().get("evaluate_threat")
            .with_context(|| format!("playbook '{}' missing evaluate_threat", self.name))?;

        let lua_event = lua.to_value(event)
            .with_context(|| format!("convert event for '{}'", self.name))?;

        let result: bool = func.call(lua_event)
            .with_context(|| format!("evaluate_threat failed in '{}'", self.name))?;
        Ok(result)
    }

    fn remediate(&self, event: &Value) -> Result<()> {
        let lua = self.lua.lock().unwrap();
        if let Ok(func) = lua.globals().get::<_, mlua::Function>("remediate") {
            let lua_event = lua.to_value(event)?;
            let _: () = func.call(lua_event)
                .with_context(|| format!("remediate failed in '{}'", self.name))?;
        }
        Ok(())
    }
}

pub struct LuaEngine {
    playbooks: HashMap<String, Arc<Playbook>>,
}

impl LuaEngine {
    pub fn new() -> Self {
        Self {
            playbooks: HashMap::new(),
        }
    }

    pub fn load_directory(&mut self, dir: &Path) -> Result<usize> {
        if !dir.exists() {
            warn!(path = %dir.display(), "Playbooks directory does not exist, skipping");
            return Ok(0);
        }

        let mut count = 0;
        for entry in fs::read_dir(dir).context("read playbooks dir")? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("lua") {
                continue;
            }
            let name = path.file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_string();
            let source = fs::read_to_string(&path)
                .with_context(|| format!("read {}", path.display()))?;

            match Playbook::new(&name, &source) {
                Ok(pb) => {
                    info!(playbook = %name, "Loaded production playbook");
                    self.playbooks.insert(name, Arc::new(pb));
                    count += 1;
                }
                Err(e) => {
                    error!(playbook = %name, error = %e, "Failed to load playbook — skipped");
                }
            }
        }
        info!(count, path = %dir.display(), "Playbooks loaded");
        Ok(count)
    }

    pub fn evaluate_all(&self, event: &Value) -> Vec<String> {
        let mut matched = Vec::new();
        for (name, pb) in &self.playbooks {
            match pb.evaluate(event) {
                Ok(true) => {
                    matched.push(name.clone());
                    if let Err(e) = pb.remediate(event) {
                        warn!(playbook = %name, error = %e, "Remediation failed");
                    }
                }
                Ok(false) => {}
                Err(e) => {
                    warn!(playbook = %name, error = %e, "Playbook evaluation error");
                }
            }
        }
        matched
    }

    pub fn playbook_count(&self) -> usize {
        self.playbooks.len()
    }
}
