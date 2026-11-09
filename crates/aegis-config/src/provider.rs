//! Configuration provider implementation.

use crate::schema::{default_config, load_config, save_config, AegisConfig};
use crate::{AegisError, AegisResult};
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use parking_lot::RwLock;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

/// File-based configuration provider with hot-reload support.
pub struct FileConfigProvider {
    config_path: PathBuf,
    config: Arc<RwLock<AegisConfig>>,
    watcher: Option<RecommendedWatcher>,
    reload_tx: watch::Sender<AegisConfig>,
}

impl FileConfigProvider {
    /// Create a new file configuration provider.
    pub async fn new(config_path: PathBuf) -> AegisResult<Self> {
        Self::new_with_watcher(config_path, true).await
    }

    /// Create a new file configuration provider with optional watcher.
    pub async fn new_with_watcher(config_path: PathBuf, watch: bool) -> AegisResult<Self> {
        // Load initial config
        let config = if config_path.exists() {
            load_config(&config_path)?
        } else {
            warn!("Config file not found at {:?}, using defaults", config_path);
            default_config()
        };

        let (reload_tx, _) = watch::channel(config.clone());
        let config = Arc::new(RwLock::new(config));

        let mut provider = Self {
            config_path,
            config,
            watcher: None,
            reload_tx,
        };

        // Start file watcher if requested
        if watch {
            provider.start_watcher().await?;
        }

        Ok(provider)
    }

    /// Start the file watcher for hot-reload.
    async fn start_watcher(&mut self) -> AegisResult<()> {
        let config_path = self.config_path.clone();
        let config = self.config.clone();
        let reload_tx = self.reload_tx.clone();

        let mut watcher = notify::recommended_watcher(
            move |res: Result<notify::Event, notify::Error>| match res {
                Ok(event) => {
                    if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                        if event.paths.iter().any(|p| p == &config_path) {
                            debug!("Config file changed, reloading...");
                            match load_config(&config_path) {
                                Ok(new_config) => {
                                    let mut guard = config.write();
                                    *guard = new_config;
                                    let _ = reload_tx.send(guard.clone());
                                    info!("Configuration reloaded from {:?}", config_path);
                                }
                                Err(e) => {
                                    error!("Failed to reload config: {}", e);
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Config watcher error: {}", e);
                }
            },
        )?;

        watcher.watch(&self.config_path, RecursiveMode::NonRecursive)?;
        self.watcher = Some(watcher);

        Ok(())
    }

    /// Get the current configuration.
    pub fn get_config(&self) -> AegisConfig {
        self.config.read().clone()
    }

    /// Get a typed configuration value.
    pub fn get<T: serde::de::DeserializeOwned>(&self, key: &str) -> AegisResult<T> {
        let config = self.config.read();
        let value =
            serde_json::to_value(&*config).map_err(|e| AegisError::Config(e.to_string()))?;

        // Navigate to the key using dot notation
        let parts: Vec<&str> = key.split('.').collect();
        let mut current = &value;
        for part in parts {
            current = current
                .get(part)
                .ok_or_else(|| AegisError::NotFound(format!("Config key not found: {}", key)))?;
        }

        serde_json::from_value(current.clone()).map_err(|e| AegisError::Config(e.to_string()))
    }

    /// Set a configuration value.
    pub fn set(&self, key: &str, value: &serde_json::Value) -> AegisResult<()> {
        let mut config = self.config.write();
        let mut value_map =
            serde_json::to_value(&*config).map_err(|e| AegisError::Config(e.to_string()))?;

        // Navigate and set the value
        let parts: Vec<&str> = key.split('.').collect();
        let mut current = &mut value_map;
        for (i, part) in parts.iter().enumerate() {
            if i == parts.len() - 1 {
                current[part] = value.clone();
            } else {
                current = current.get_mut(part).ok_or_else(|| {
                    AegisError::NotFound(format!("Config path not found: {}", key))
                })?;
            }
        }

        // Validate and update
        let new_config: AegisConfig =
            serde_json::from_value(value_map).map_err(|e| AegisError::Config(e.to_string()))?;

        new_config.validate()?;
        *config = new_config;

        // Save to disk
        save_config(&*config, &self.config_path)?;

        // Notify watchers
        let _ = self.reload_tx.send(config.clone());

        Ok(())
    }

    /// Watch for configuration changes (returns full config receiver for simplicity).
    pub async fn watch(&self, _key: &str) -> AegisResult<watch::Receiver<AegisConfig>> {
        Ok(self.reload_tx.subscribe())
    }

    /// Reload configuration from disk.
    pub async fn reload(&self) -> AegisResult<()> {
        let new_config = load_config(&self.config_path)?;
        new_config.validate()?;

        let mut config = self.config.write();
        *config = new_config;

        let _ = self.reload_tx.send(config.clone());
        info!("Configuration manually reloaded");

        Ok(())
    }
}

#[async_trait::async_trait]
impl aegis_core::traits::ConfigProvider for FileConfigProvider {
    fn get<T: serde::de::DeserializeOwned>(&self, key: &str) -> AegisResult<T> {
        self.get(key)
    }

    async fn set(&self, key: &str, value: &serde_json::Value) -> AegisResult<()> {
        self.set(key, value)
    }

    async fn watch(
        &self,
        key: &str,
    ) -> AegisResult<tokio::sync::watch::Receiver<serde_json::Value>> {
        // Return a receiver that filters the full config
        let full_rx = self.reload_tx.subscribe();
        let key = key.to_string();
        let (tx, rx) = tokio::sync::watch::channel(serde_json::Value::Null);

        tokio::spawn(async move {
            let mut full_rx = full_rx;
            loop {
                full_rx.changed().await.ok();
                let full = full_rx.borrow().clone();
                if let Some(val) = extract_key(&serde_json::to_value(&full).unwrap(), &key) {
                    let _ = tx.send(val);
                }
            }
        });

        Ok(rx)
    }

    async fn reload(&self) -> AegisResult<()> {
        self.reload().await
    }

    fn validate(&self) -> AegisResult<()> {
        self.config.read().validate()
    }
}

/// Extract a nested key from a JSON value using dot notation.
fn extract_key(value: &serde_json::Value, key: &str) -> Option<serde_json::Value> {
    let parts: Vec<&str> = key.split('.').collect();
    let mut current = value;
    for part in parts {
        current = current.get(part)?;
    }
    Some(current.clone())
}

/// Configuration watcher for external components.
pub struct ConfigWatcher {
    receiver: watch::Receiver<AegisConfig>,
}

impl ConfigWatcher {
    pub fn new(receiver: watch::Receiver<AegisConfig>) -> Self {
        Self { receiver }
    }

    /// Wait for configuration change.
    pub async fn wait_for_change(&mut self) -> AegisResult<AegisConfig> {
        self.receiver
            .changed()
            .await
            .map_err(|_| AegisError::Internal("Config watcher channel closed".into()))?;
        Ok(self.receiver.borrow().clone())
    }

    /// Get current config.
    pub fn current(&self) -> AegisConfig {
        self.receiver.borrow().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_file_config_provider() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("test_config.yaml");

        // Create initial config file with all required fields from default config
        let default_config = crate::schema::default_config();
        let yaml = serde_yaml::to_string(&default_config).unwrap();
        std::fs::write(&config_path, yaml).unwrap();

        // Create provider without watcher to avoid blocking in test runtime
        let provider = FileConfigProvider::new_with_watcher(config_path.clone(), false)
            .await
            .unwrap();

        // Test get
        let ws_private: u64 = provider.get("service.working_set_private_mb").unwrap();
        assert_eq!(ws_private, 150);

        // Test set (this will write to file)
        provider
            .set("service.working_set_private_mb", &serde_json::json!(200))
            .unwrap();
        let ws_private: u64 = provider.get("service.working_set_private_mb").unwrap();
        assert_eq!(ws_private, 200);

        // Test that config was persisted by creating a new provider
        let provider2 = FileConfigProvider::new_with_watcher(config_path, false)
            .await
            .unwrap();
        let ws_private: u64 = provider2.get("service.working_set_private_mb").unwrap();
        assert_eq!(ws_private, 200);
    }
}
