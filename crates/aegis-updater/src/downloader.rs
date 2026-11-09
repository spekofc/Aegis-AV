//! Update downloader.

use aegis_core::{AegisError, AegisResult};
use reqwest::Client;
use std::path::Path;
use tokio::io::AsyncWriteExt;
use tracing::info;

/// Download configuration.
#[derive(Debug, Clone)]
pub struct DownloadConfig {
    pub timeout_secs: u64,
    pub max_retries: u32,
    pub chunk_size: usize,
    pub verify_certificates: bool,
}

impl Default for DownloadConfig {
    fn default() -> Self {
        Self {
            timeout_secs: 300,
            max_retries: 3,
            chunk_size: 1024 * 1024, // 1 MB
            verify_certificates: true,
        }
    }
}

/// Downloader for update components.
pub struct Downloader {
    client: Client,
    config: DownloadConfig,
}

impl Downloader {
    /// Create a new downloader.
    pub fn new(config: DownloadConfig) -> AegisResult<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .danger_accept_invalid_certs(!config.verify_certificates)
            .build()
            .map_err(|e| AegisError::External(e.into()))?;

        Ok(Self { client, config })
    }

    /// Download a component.
    pub async fn download(&self, url: &str, dest: &Path) -> AegisResult<u64> {
        info!("Downloading {} to {:?}", url, dest);
        let mut response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| AegisError::External(e.into()))?;

        if !response.status().is_success() {
            return Err(AegisError::External(anyhow::anyhow!(
                "Download failed: {}",
                response.status()
            )));
        }

        let mut downloaded = 0u64;
        let mut file = tokio::fs::File::create(dest)
            .await
            .map_err(|e| AegisError::Io(e))?;

        use tokio::io::AsyncWriteExt;

        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| AegisError::External(e.into()))?
        {
            file.write_all(&chunk)
                .await
                .map_err(|e| AegisError::Io(e))?;
            downloaded += chunk.len() as u64;
        }

        file.flush().await.map_err(|e| AegisError::Io(e))?;
        Ok(downloaded)
    }
}
