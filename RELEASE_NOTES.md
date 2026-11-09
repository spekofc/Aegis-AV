# AEGIS AV v0.1.0-alpha.1

**Primeiro MVP do AEGIS AV — Antivírus open-source em Rust**

## ✅ Funcionalidades implementadas

### CLI (`aegis.exe`)
| Comando | Descrição |
|---------|-----------|
| `scan <path> [-r]` | Varredura de arquivo ou diretório (recursivo com `-r`) |
| `quarantine add <path> <nome> <tipo>` | Quarentena com criptografia AES-256-GCM |
| `quarantine list [--json]` | Lista itens em quarentena |
| `quarantine restore <id> <dest>` | Restaura arquivo (descriptografa) |
| `quarantine destroy <id>` | Destrói permanentemente |
| `signatures status [--json]` | Status do banco de assinaturas |
| `signatures add <path> <família> <tipo> <severidade>` | Adiciona assinatura por hash |
| `status [--json]` | Status do motor e banco |
| `selftest [--json]` | Auto-teste (arquivo limpo + EICAR) |
| `--json` (global) | Saída estruturada para automação |

### Motor de Varredura
- **Hash lookup** (SHA-256) — detecção instantânea de malware conhecido
- **Pattern matching** (Aho-Corasick) — assinaturas de bytes/padrões
- **Heurísticas** — executáveis em diretórios temporários
- **PE Analysis** — análise estática de executáveis Windows (seções, imports, entropia)

### Quarentena
- Criptografia AES-256-GCM com chave persistente em `metadata.json`
- Integridade via hash SHA-256 verificado na restauração
- Metadados em JSON (id, threat_name, threat_type, size, timestamps)

### Banco de Assinaturas
- SQLite com integridade Merkle Tree
- Suporte a hash signatures e pattern signatures
- Versionamento e rollback

## 📦 Download

| Arquivo | SHA256 |
|---------|--------|
| `aegis-v0.1.0-alpha.1-windows-x64.zip` | *(calculado no release)* |

## ⚠️ Notas importantes
- **Alpha** — não usar em produção
- Chave de criptografia da quarentena gerada localmente (não incluída no binário)
- Banco de assinaturas vazio por padrão — adicione assinaturas via `signatures add` ou importe
- Requer Windows 10+ (x64)

## 🔧 Build
```bash
cargo build --release --workspace
```

## 🧪 Testes
```bash
cargo test --workspace
# 38 testes passam
```

## 🔗 Links
- Repositório: https://github.com/spekofc/Aegis-AV
- Issues: https://github.com/spekofc/Aegis-AV/issues