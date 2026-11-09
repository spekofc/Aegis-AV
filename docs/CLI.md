# CLI Reference

## Global Options

| Option | Description |
|--------|-------------|
| `--json` | Structured JSON output for all commands |
| `-h, --help` | Show help |
| `-V, --version` | Print version |

## Commands

### `aegis scan`

Scan files or directories for threats.

```bash
aegis scan <PATH> [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `-r, --recursive` | Scan directory recursively |

**Examples:**
```bash
# Scan single file
aegis scan sample.exe

# Scan directory recursively
aegis scan C:\samples -r

# JSON output
aegis scan sample.exe --json

# Recursive with JSON
aegis scan C:\samples -r --json
```

**Exit Codes:**
- `0` - Clean
- `1` - Threat detected
- `2` - Error

### `aegis quarantine`

Manage quarantined items.

```bash
aegis quarantine <SUBCOMMAND>
```

#### `quarantine add`

Quarantine a file (encrypts with AES-256-GCM).

```bash
aegis quarantine add <PATH> <THREAT_NAME> <THREAT_TYPE>
```

| Argument | Description |
|----------|-------------|
| `PATH` | File to quarantine |
| `THREAT_NAME` | Detection name (e.g., "Trojan.Generic") |
| `THREAT_TYPE` | Type: trojan, virus, worm, ransomware, rootkit, spyware, adware, dropper, loader, backdoor, packer, unknown |

**Example:**
```bash
aegis quarantine add malware.exe "Trojan.Generic" trojan
```

#### `quarantine list`

List all quarantined items.

```bash
aegis quarantine list [--json]
```

#### `quarantine restore`

Restore a quarantined file (decrypts automatically).

```bash
aegis quarantine restore <ID> <DESTINATION>
```

| Argument | Description |
|----------|-------------|
| `ID` | Quarantine item UUID |
| `DESTINATION` | Output path |

**Example:**
```bash
aegis quarantine restore 01a1c1ad-15a8-750b-8903-9320079eb530 C:\restored\malware.exe
```

#### `quarantine destroy`

Permanently destroy a quarantined item.

```bash
aegis quarantine destroy <ID>
```

### `aegis signatures`

Manage signature database.

```bash
aegis signatures <SUBCOMMAND>
```

#### `signatures status`

Show database statistics.

```bash
aegis signatures status [--json]
```

**Output:**
```json
{
  "signature_count": 2,
  "pattern_count": 0,
  "version": "0.1.0",
  "size_bytes": 40960
}
```

#### `signatures add`

Add a hash signature from a file.

```bash
aegis signatures add <PATH> <FAMILY> <THREAT_TYPE> <SEVERITY>
```

| Argument | Description |
|----------|-------------|
| `PATH` | File to hash and add |
| `FAMILY` | Threat family name |
| `THREAT_TYPE` | trojan, virus, worm, ransomware, rootkit, spyware, adware, dropper, loader, backdoor, packer, unknown |
| `SEVERITY` | 1-10 (10 = most severe) |

**Example:**
```bash
aegis signatures add malware.exe "Trojan.Generic" trojan 8
```

### `aegis status`

Show engine and signature database status.

```bash
aegis status [--json]
```

**Output:**
```
AEGIS AV Status
===============
Version: 0.1.0
Engine:
  Files scanned: 42
  Detections: 5
  Bytes scanned: 1048576
  Scan errors: 0
Signatures:
  Count: 127
  Database size: 204800 bytes
```

### `aegis selftest`

Run internal self-test (clean file + EICAR).

```bash
aegis selftest [--json]
```

**Output:**
```
Self-test results:
  Clean file scan: PASS
  EICAR scan: PASS
All tests PASSED
```

### `aegis realtime` (Not Implemented)

Real-time protection control.

```bash
aegis realtime <start|stop|status>
```

### `aegis update` (Not Implemented)

Update engine and signatures.

```bash
aegis update <check|apply|rollback>
```

### `aegis service` (Not Implemented)

Windows service management.

```bash
aegis service <install|uninstall|start|stop|status>
```

### `aegis config` (Not Implemented)

Configuration management.

```bash
aegis config <show|set|validate>
```

## JSON Output Format

All commands support `--json` for structured output.

### Scan Result

```json
[
  {
    "disposition": "Malicious|Suspicious|Clean|Error",
    "threat_type": "Trojan|Virus|Worm|...",
    "threat_name": "Trojan.Generic",
    "confidence": 1.0,
    "engine": "Hash|Pattern|Heuristic|PE",
    "matched_ids": [1, 2],
    "details": { "method": "hash" },
    "duration": { "secs": 0, "nanos": 227400 }
  }
]
```

### Quarantine Item

```json
{
  "id": "01a1c1ad-15a8-750b-8903-9320079eb530",
  "path": "C:\\AEGIS-AV\\data\\Quarantine\\...",
  "original_path": "data\\eicar.com",
  "threat_name": "EICAR-Test-File",
  "threat_type": "Virus",
  "size": 63,
  "hash": [34, 28, 105, ...],
  "quarantined_at": 1794250708392085100,
  "encrypted": true
}
```

### Status

```json
{
  "engine": {
    "version": "0.1.0",
    "files_scanned": 42,
    "detections": 5,
    "bytes_scanned": 1048576,
    "scan_errors": 0
  },
  "signatures": {
    "count": 127,
    "size_bytes": 204800
  }
}
```

### Self-Test

```json
{
  "tests": [
    { "name": "clean_file", "passed": true },
    { "name": "eicar_scan", "passed": true }
  ],
  "all_passed": true
}
```

## Threat Types

| Type | Description |
|------|-------------|
| `trojan` | Trojan horse |
| `virus` | Self-replicating virus |
| `worm` | Network worm |
| `ransomware` | File-encrypting ransomware |
| `rootkit` | Kernel/user-mode rootkit |
| `spyware` | Information stealer |
| `adware` | Advertising malware |
| `dropper` | Malware dropper |
| `loader` | Malware loader |
| `backdoor` | Remote access backdoor |
| `packer` | Runtime packer/protector |
| `unknown` | Unclassified |

## Severity Levels

| Level | Description |
|-------|-------------|
| 1-2 | Low |
| 3-4 | Medium |
| 5-7 | High |
| 8-10 | Critical |

## Disposition Values

| Value | Meaning |
|-------|---------|
| `Clean` | No threat detected |
| `Suspicious` | Heuristic/behavioral anomaly |
| `Malicious` | Confirmed threat |
| `Error` | Scan failed |

## Detection Engines

| Engine | Speed | Confidence | Use Case |
|--------|-------|------------|----------|
| `Hash` | Fastest | 100% | Known malware |
| `Pattern` | Fast | 90% | Variants, families |
| `Heuristic` | Medium | 60% | Unknown executables |
| `PE` | Slowest | Varies | Structural anomalies |

## Examples

### Batch Scan with JSON

```bash
# Scan directory, output JSON lines
aegis scan C:\samples -r --json | jq -c '.[] | select(.disposition=="Malicious")'
```

### Automation Script (PowerShell)

```powershell
$result = aegis scan suspicious.exe --json | ConvertFrom-Json
if ($result[0].disposition -eq "Malicious") {
    Write-Host "THREAT: $($result[0].threat_name)"
    aegis quarantine add suspicious.exe $result[0].threat_name $result[0].threat_type
}
```

### CI Integration

```yaml
# GitHub Actions
- name: Scan artifacts
  run: |
    aegis scan ./dist -r --json > scan-results.json
    if (jq -e '.[] | select(.disposition=="Malicious")' scan-results.json); then
      echo "Malware detected!"
      exit 1
    fi
```