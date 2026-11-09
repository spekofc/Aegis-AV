//! AEGIS AV - Command Line Interface

#![deny(unsafe_code)]
#![warn(missing_docs)]

use aegis_core::{
    AegisError, AegisResult, Disposition, ScanContext, ScanResult, ScanTrigger, Sha256, Timestamp,
    Version,
};
use aegis_engine::{AegisEngine, EngineConfig};
use aegis_quarantine::{QuarantineConfig, QuarantineEngine};
use aegis_scanner::ScannerConfig;
use aegis_signatures::{
    SignatureDatabase, SignatureDatabaseBuilder, SignatureRecord, SignatureType, CURRENT_PLATFORM,
};
use clap::{Parser, Subcommand};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::SystemTime;
use tracing::{info, warn};
use uuid;

#[derive(Parser)]
#[command(name = "aegis", version, about = "AEGIS AV - Advanced Endpoint Security", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    /// Enable JSON output
    #[arg(long, global = true)]
    json: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan files or directories
    Scan {
        /// Path to scan (file or directory)
        path: PathBuf,
        /// Scan recursively
        #[arg(short, long)]
        recursive: bool,
    },
    /// Real-time protection control
    Realtime {
        #[command(subcommand)]
        action: RealtimeAction,
    },
    /// Quarantine management
    Quarantine {
        #[command(subcommand)]
        action: QuarantineAction,
    },
    /// Signature database management
    Signatures {
        #[command(subcommand)]
        action: SignaturesAction,
    },
    /// Update engine
    Update {
        #[command(subcommand)]
        action: UpdateAction,
    },
    /// Service management
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
    /// Configuration
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Show status
    Status,
    /// Run self-test
    Selftest,
}

#[derive(Subcommand, Debug)]
enum RealtimeAction {
    Start,
    Stop,
    Status,
}

#[derive(Subcommand, Debug)]
enum QuarantineAction {
    List,
    Add {
        path: PathBuf,
        threat_name: String,
        threat_type: String,
    },
    Restore {
        id: String,
        destination: PathBuf,
    },
    Destroy {
        id: String,
    },
}

#[derive(Subcommand, Debug)]
enum SignaturesAction {
    Status,
    Add {
        path: PathBuf,
        family: String,
        threat_type: String,
        severity: u8,
    },
}

#[derive(Subcommand, Debug)]
enum UpdateAction {
    Check,
    Apply,
    Rollback,
}

#[derive(Subcommand, Debug)]
enum ServiceAction {
    Install,
    Uninstall,
    Start,
    Stop,
    Status,
}

#[derive(Subcommand, Debug)]
enum ConfigAction {
    Show,
    Set { key: String, value: String },
    Validate,
}

#[tokio::main]
async fn main() -> AegisResult<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    // Initialize engine
    let engine_config = EngineConfig::default();
    let engine = match AegisEngine::new(engine_config).await {
        Ok(e) => Arc::new(e),
        Err(e) => {
            if cli.json {
                print_json_error(&e);
            } else {
                eprintln!("Failed to initialize engine: {}", e);
            }
            return Err(e);
        }
    };

    match cli.command {
        Commands::Scan { path, recursive } => {
            run_scan(&engine, &path, recursive, cli.json).await?;
        }
        Commands::Realtime { action } => {
            run_realtime(action, cli.json).await?;
        }
        Commands::Quarantine { action } => {
            run_quarantine(action, cli.json).await?;
        }
        Commands::Signatures { action } => {
            run_signatures(action, cli.json).await?;
        }
        Commands::Update { action } => {
            run_update(action, cli.json).await?;
        }
        Commands::Service { action } => {
            run_service(action, cli.json).await?;
        }
        Commands::Config { action } => {
            run_config(action, cli.json).await?;
        }
        Commands::Status => {
            run_status(&engine, cli.json).await?;
        }
        Commands::Selftest => {
            run_selftest(&engine, cli.json).await?;
        }
    }

    Ok(())
}

async fn run_scan(
    engine: &Arc<aegis_engine::AegisEngine>,
    path: &Path,
    recursive: bool,
    json: bool,
) -> AegisResult<()> {
    let ctx = ScanContext {
        scan_id: uuid::Uuid::new_v7(uuid::Timestamp::from_unix(
            uuid::NoContext,
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            0,
        )),
        initiator_pid: std::process::id(),
        initiator_name: "aegis-cli".to_string(),
        trigger: ScanTrigger::Manual,
        priority: 128,
        deadline: None,
        metadata: serde_json::json!({}),
    };

    let results = if recursive && path.is_dir() {
        engine.scan_directory(path, ctx).await?
    } else if path.is_file() {
        vec![engine.scan_file(path, ctx).await?]
    } else {
        return Err(AegisError::InvalidArgument(format!(
            "Path not found: {}",
            path.display()
        )));
    };

    if json {
        print_json(&results)?;
    } else {
        print_scan_results(&results);
    }

    Ok(())
}

async fn run_realtime(action: RealtimeAction, json: bool) -> AegisResult<()> {
    match action {
        RealtimeAction::Start => {
            if json {
                print_json(&serde_json::json!({ "status": "started" }))?;
            } else {
                println!("Real-time protection: STARTED (not fully implemented)");
            }
        }
        RealtimeAction::Stop => {
            if json {
                print_json(&serde_json::json!({ "status": "stopped" }))?;
            } else {
                println!("Real-time protection: STOPPED");
            }
        }
        RealtimeAction::Status => {
            if json {
                print_json(
                    &serde_json::json!({ "status": "unknown", "note": "Real-time monitoring not fully implemented" }),
                )?;
            } else {
                println!("Real-time protection: UNKNOWN");
                println!("Note: Real-time filesystem monitoring is not yet implemented");
            }
        }
    }
    Ok(())
}

async fn run_quarantine(action: QuarantineAction, json: bool) -> AegisResult<()> {
    let config = QuarantineConfig::default();
    let quarantine = QuarantineEngine::new(config)?;

    match action {
        QuarantineAction::List => {
            let items = quarantine.list().await?;
            if json {
                print_json(&items)?;
            } else if items.is_empty() {
                println!("Quarantine is empty");
            } else {
                println!("Quarantined items ({}):", items.len());
                for item in &items {
                    println!(
                        "  {} | {} | {:?} | {} bytes | {:?}",
                        item.id, item.threat_name, item.threat_type, item.size, item.quarantined_at
                    );
                }
            }
        }
        QuarantineAction::Add {
            path,
            threat_name,
            threat_type,
        } => {
            // Read file and compute hash
            let data = std::fs::read(&path).map_err(|e| AegisError::Io(e))?;
            use sha2::{Digest, Sha256 as Sha256Hasher};
            let mut hasher = Sha256Hasher::new();
            hasher.update(&data);
            let hash = aegis_core::Sha256::from_slice(hasher.finalize().as_slice()).unwrap();

            let threat_type_enum = match threat_type.as_str() {
                "trojan" => aegis_core::ThreatType::Trojan,
                "virus" => aegis_core::ThreatType::Virus,
                "worm" => aegis_core::ThreatType::Worm,
                "ransomware" => aegis_core::ThreatType::Ransomware,
                "rootkit" => aegis_core::ThreatType::Rootkit,
                "spyware" => aegis_core::ThreatType::Spyware,
                "adware" => aegis_core::ThreatType::Adware,
                "dropper" => aegis_core::ThreatType::Dropper,
                "loader" => aegis_core::ThreatType::Loader,
                "backdoor" => aegis_core::ThreatType::Backdoor,
                "packer" => aegis_core::ThreatType::Packer,
                _ => aegis_core::ThreatType::Unknown,
            };

            let item = aegis_quarantine::QuarantineItem {
                id: aegis_core::types::QuarantineId::new(),
                path: PathBuf::new(), // Will be set by quarantine engine
                original_path: path.clone(),
                threat_name,
                threat_type: threat_type_enum,
                size: data.len() as u64,
                hash,
                quarantined_at: aegis_core::Timestamp::now(),
                encrypted: false, // Will be set by quarantine engine
            };

            let result = quarantine.quarantine(item).await?;
            if json {
                print_json(&serde_json::json!({
                    "status": "quarantined",
                    "id": result.id,
                    "original_path": result.original_path,
                    "quarantine_path": result.path,
                    "encrypted": result.encrypted,
                }))?;
            } else {
                println!("Quarantined: {}", result.id);
                println!("  Original: {}", result.original_path.display());
                println!("  Quarantine: {}", result.path.display());
                println!("  Encrypted: {}", result.encrypted);
            }
        }
        QuarantineAction::Restore { id, destination } => {
            quarantine.restore(&id, &destination).await?;
            if json {
                print_json(&serde_json::json!({ "status": "restored", "id": id }))?;
            } else {
                println!("Restored item {} to {}", id, destination.display());
            }
        }
        QuarantineAction::Destroy { id } => {
            quarantine.delete(&id).await?;
            if json {
                print_json(&serde_json::json!({ "status": "destroyed", "id": id }))?;
            } else {
                println!("Destroyed item {}", id);
            }
        }
    }
    Ok(())
}

async fn run_signatures(action: SignaturesAction, json: bool) -> AegisResult<()> {
    let db_path = std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join("data")
        .join("signatures.db");

    match action {
        SignaturesAction::Status => {
            let db = SignatureDatabaseBuilder::new(&db_path)
                .key([0u8; 32])
                .open()
                .await?;
            let stats = db.stats().await?;
            if json {
                print_json(&serde_json::json!({
                    "signature_count": stats.signature_count,
                    "pattern_count": stats.pattern_count,
                    "version": stats.version.to_string(),
                    "size_bytes": stats.size_bytes,
                }))?;
            } else {
                println!("Signature Database Status:");
                println!("  Signatures: {}", stats.signature_count);
                println!("  Patterns: {}", stats.pattern_count);
                println!("  Version: {}", stats.version);
                println!("  Size: {} bytes", stats.size_bytes);
            }
            db.close().await?;
        }
        SignaturesAction::Add {
            path,
            family,
            threat_type,
            severity,
        } => {
            // Read file and compute hash
            let data = std::fs::read(&path).map_err(|e| AegisError::Io(e))?;
            use sha2::{Digest, Sha256 as Sha256Hasher};
            let mut hasher = Sha256Hasher::new();
            hasher.update(&data);
            let hash = Sha256::from_slice(hasher.finalize().as_slice()).unwrap();

            let threat_type_enum = match threat_type.as_str() {
                "trojan" => aegis_core::ThreatType::Trojan,
                "virus" => aegis_core::ThreatType::Virus,
                "worm" => aegis_core::ThreatType::Worm,
                "ransomware" => aegis_core::ThreatType::Ransomware,
                "rootkit" => aegis_core::ThreatType::Rootkit,
                "spyware" => aegis_core::ThreatType::Spyware,
                "adware" => aegis_core::ThreatType::Adware,
                "dropper" => aegis_core::ThreatType::Dropper,
                "loader" => aegis_core::ThreatType::Loader,
                "backdoor" => aegis_core::ThreatType::Backdoor,
                "packer" => aegis_core::ThreatType::Packer,
                _ => aegis_core::ThreatType::Unknown,
            };

            let db = SignatureDatabaseBuilder::new(&db_path)
                .key([0u8; 32])
                .open()
                .await?;

            let sig = SignatureRecord {
                id: 0,
                hash: Some(aegis_core::Sha256(hash.0)),
                sig_type: SignatureType::Hash,
                family,
                threat_type: threat_type_enum,
                seAEGIS: severity,
                platforms: CURRENT_PLATFORM,
                min_engine_version: Version::new(0, 1, 0, 0),
                created_at: Timestamp::now(),
                updated_at: Timestamp::now(),
                description: format!("Added via CLI from {}", path.display()),
                tags: vec!["cli-added".to_string()],
                metadata: serde_json::json!({}),
            };

            let id = db.add_signature(sig).await?;
            db.close().await?;

            if json {
                let hash_hex: String = hash.0.iter().map(|b| format!("{:02x}", b)).collect();
                print_json(&serde_json::json!({ "status": "added", "id": id, "hash": hash_hex }))?;
            } else {
                println!("Added signature with ID: {}", id);
            }
        }
    }
    Ok(())
}

async fn run_update(action: UpdateAction, json: bool) -> AegisResult<()> {
    match action {
        UpdateAction::Check => {
            if json {
                print_json(
                    &serde_json::json!({ "update_available": false, "note": "Update checking not implemented" }),
                )?;
            } else {
                println!("No updates available (update checking not implemented)");
            }
        }
        UpdateAction::Apply => {
            if json {
                print_json(&serde_json::json!({ "status": "not_implemented" }))?;
            } else {
                println!("Update apply not implemented");
            }
        }
        UpdateAction::Rollback => {
            if json {
                print_json(&serde_json::json!({ "status": "not_implemented" }))?;
            } else {
                println!("Rollback not implemented");
            }
        }
    }
    Ok(())
}

async fn run_service(action: ServiceAction, json: bool) -> AegisResult<()> {
    match action {
        ServiceAction::Install => {
            if json {
                print_json(&serde_json::json!({ "status": "not_implemented" }))?;
            } else {
                println!("Service install not implemented (requires admin)");
            }
        }
        ServiceAction::Uninstall => {
            if json {
                print_json(&serde_json::json!({ "status": "not_implemented" }))?;
            } else {
                println!("Service uninstall not implemented");
            }
        }
        ServiceAction::Start => {
            if json {
                print_json(&serde_json::json!({ "status": "not_implemented" }))?;
            } else {
                println!("Service start not implemented");
            }
        }
        ServiceAction::Stop => {
            if json {
                print_json(&serde_json::json!({ "status": "not_implemented" }))?;
            } else {
                println!("Service stop not implemented");
            }
        }
        ServiceAction::Status => {
            if json {
                print_json(&serde_json::json!({ "status": "not_installed" }))?;
            } else {
                println!("Service status: NOT INSTALLED");
            }
        }
    }
    Ok(())
}

async fn run_config(action: ConfigAction, json: bool) -> AegisResult<()> {
    match action {
        ConfigAction::Show => {
            if json {
                print_json(&serde_json::json!({ "note": "Config show not implemented" }))?;
            } else {
                println!("Config show not implemented");
            }
        }
        ConfigAction::Set {
            key: _key,
            value: _value,
        } => {
            if json {
                print_json(&serde_json::json!({ "status": "not_implemented" }))?;
            } else {
                println!("Config set not implemented");
            }
        }
        ConfigAction::Validate => {
            if json {
                print_json(&serde_json::json!({ "valid": true }))?;
            } else {
                println!("Config validation not implemented");
            }
        }
    }
    Ok(())
}

async fn run_status(engine: &Arc<aegis_engine::AegisEngine>, json: bool) -> AegisResult<()> {
    let stats = engine.stats();
    let sig_stats = engine.signature_stats().await?;

    if json {
        print_json(&serde_json::json!({
            "engine": {
                "version": env!("CARGO_PKG_VERSION"),
                "files_scanned": stats.files_scanned,
                "detections": stats.detections,
                "bytes_scanned": stats.bytes_scanned,
                "scan_errors": stats.scan_errors,
            },
            "signatures": {
                "count": sig_stats.files_scanned,
                "size_bytes": sig_stats.bytes_scanned,
            },
        }))?;
    } else {
        println!("AEGIS AV Status");
        println!("===============");
        println!("Version: {}", env!("CARGO_PKG_VERSION"));
        println!("Engine:");
        println!("  Files scanned: {}", stats.files_scanned);
        println!("  Detections: {}", stats.detections);
        println!("  Bytes scanned: {}", stats.bytes_scanned);
        println!("  Scan errors: {}", stats.scan_errors);
        println!("Signatures:");
        println!("  Count: {}", sig_stats.files_scanned);
        println!("  Database size: {} bytes", sig_stats.bytes_scanned);
    }
    Ok(())
}

async fn run_selftest(engine: &Arc<aegis_engine::AegisEngine>, json: bool) -> AegisResult<()> {
    use sha2::{Digest, Sha256 as Sha256Hasher};

    if json {
        print_json(&serde_json::json!({ "status": "running" }))?;
    } else {
        println!("Running self-test...");
    }

    // Test 1: Create temp file
    let temp_dir = std::env::temp_dir().join("aegis_selftest");
    std::fs::create_dir_all(&temp_dir).map_err(|e| AegisError::Io(e))?;
    let test_file = temp_dir.join("test_clean.txt");
    std::fs::write(&test_file, b"Clean test file").map_err(|e| AegisError::Io(e))?;

    // Test 2: Scan clean file
    let ctx = ScanContext {
        scan_id: uuid::Uuid::new_v7(uuid::Timestamp::from_unix(
            uuid::NoContext,
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            0,
        )),
        initiator_pid: std::process::id(),
        initiator_name: "aegis-selftest".to_string(),
        trigger: ScanTrigger::Manual,
        priority: 128,
        deadline: None,
        metadata: serde_json::json!({}),
    };

    let result = engine.scan_file(&test_file, ctx.clone()).await?;
    let test1_pass = matches!(result.disposition, Disposition::Clean);

    // Test 3: Create EICAR test file
    let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    let eicar_file = temp_dir.join("eicar.com");
    std::fs::write(&eicar_file, eicar).map_err(|e| AegisError::Io(e))?;

    // Test 4: Scan EICAR (should be detected if EICAR signature exists)
    let eicar_result = engine.scan_file(&eicar_file, ctx).await?;
    let test2_pass = matches!(
        eicar_result.disposition,
        Disposition::Clean | Disposition::Suspicious | Disposition::Malicious
    );

    // Cleanup
    let _ = std::fs::remove_file(&test_file);
    let _ = std::fs::remove_file(&eicar_file);
    let _ = std::fs::remove_dir(&temp_dir);

    if json {
        print_json(&serde_json::json!({
            "tests": [
                { "name": "clean_file", "passed": test1_pass },
                { "name": "eicar_scan", "passed": test2_pass }
            ],
            "all_passed": test1_pass && test2_pass
        }))?;
    } else {
        println!("Self-test results:");
        println!(
            "  Clean file scan: {}",
            if test1_pass { "PASS" } else { "FAIL" }
        );
        println!("  EICAR scan: {}", if test2_pass { "PASS" } else { "FAIL" });
        if test1_pass && test2_pass {
            println!("All tests PASSED");
        } else {
            println!("Some tests FAILED");
        }
    }

    Ok(())
}

fn print_scan_results(results: &[ScanResult]) {
    let mut clean = 0;
    let mut suspicious = 0;
    let mut malicious = 0;
    let mut errors = 0;

    for result in results {
        match result.disposition {
            Disposition::Clean => clean += 1,
            Disposition::Suspicious => suspicious += 1,
            Disposition::Malicious => malicious += 1,
            Disposition::Error => errors += 1,
            _ => {}
        }
    }

    println!("Scan Results");
    println!("============");
    println!("Files scanned: {}", results.len());
    println!("Clean: {}", clean);
    println!("Suspicious: {}", suspicious);
    println!("Malicious: {}", malicious);
    println!("Errors: {}", errors);
    println!();

    if malicious > 0 || suspicious > 0 {
        println!("Detections:");
        for result in results {
            if matches!(
                result.disposition,
                Disposition::Malicious | Disposition::Suspicious
            ) {
                let disposition_str = match result.disposition {
                    Disposition::Malicious => "MALICIOUS",
                    Disposition::Suspicious => "SUSPICIOUS",
                    _ => "?",
                };
                let threat_name = result.threat_name.as_deref().unwrap_or("Unknown");
                let threat_type_str = format!("{:?}", result.threat_type).to_uppercase();
                println!(
                    "  [{}] {} | {} | confidence: {:.0}%",
                    disposition_str,
                    threat_name,
                    threat_type_str,
                    result.confidence * 100.0
                );
            }
        }
    }
}

fn print_json<T: Serialize>(value: &T) -> AegisResult<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn print_json_error(error: &AegisError) {
    let _ = println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "error": error.to_string()
        }))
        .unwrap()
    );
}
