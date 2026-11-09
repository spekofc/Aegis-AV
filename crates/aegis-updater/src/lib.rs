//! AEGIS AV - Update Engine

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod downloader;
pub mod installer;
pub mod manifest;

pub use downloader::{DownloadConfig, Downloader};
pub use installer::{InstallConfig, Installer};
pub use manifest::{ComponentUpdate, UpdateManifest};
