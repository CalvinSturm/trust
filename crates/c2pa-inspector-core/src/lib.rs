use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use c2pa::assertions::Actions;
use c2pa::validation_results::ValidationState;
use c2pa::{settings, Reader};
use serde::Serialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

const SCHEMA_VERSION: u32 = 1;
const TOOL_NAME: &str = "c2pa-inspect";

#[derive(Debug, Clone)]
pub enum TrustMode {
    Off,
    Default,
    CustomPem { pem_path: PathBuf },
}

#[derive(Debug, Clone)]
pub struct InspectOptions {
    pub trust: TrustMode,
    pub max_actions: usize,
    pub max_ingredients: usize,
    pub max_errors: usize,
}

impl Default for InspectOptions {
    fn default() -> Self {
        Self {
            trust: TrustMode::Off,
            max_actions: 64,
            max_ingredients: 64,
            max_errors: 16,
        }
    }
}

#[derive(Debug, Clone)]
pub struct InputMeta {
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub format_hint: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct C2paReport {
    pub tool: ToolInfo,
    pub input: InputSection,
    pub credentials: CredentialsSection,
    pub validation: ValidationSection,
    pub signer: SignerSection,
    pub actions: Vec<ActionItem>,
    pub ingredients: Vec<IngredientItem>,
}

#[derive(Debug, Serialize)]
pub struct ToolInfo {
    pub name: String,
    pub schema_version: u32,
}

#[derive(Debug, Serialize)]
pub struct InputSection {
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format_hint: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CredentialsSection {
    pub present: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_manifest_label: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ValidationSection {
    pub trust_mode: String,
    pub state: String,
    pub trusted: bool,
    pub errors: Vec<ValidationErr>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ValidationErr {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct SignerSection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_sha256: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ActionItem {
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub when: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software: Option<String>,
    pub parameters: Value,
}

#[derive(Debug, Serialize)]
pub struct IngredientItem {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relationship: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<HashRef>,
}

#[derive(Debug, Serialize)]
pub struct HashRef {
    pub alg: String,
    pub value: String,
}

struct SettingsGuard;

impl SettingsGuard {
    fn apply(mode: &TrustMode) -> Result<Self> {
        settings::reset_default_settings().context("reset C2PA settings")?;
        settings::load_settings_from_str(r#"{"verify":{"remote_manifest_fetch":false}}"#, "json")
            .context("disable remote manifest fetch")?;
        match mode {
            TrustMode::Off => {
                settings::load_settings_from_str(r#"{"verify":{"verify_trust":false}}"#, "json")
                    .context("set trust mode off")?;
            }
            TrustMode::Default => {
                settings::load_settings_from_str(r#"{"verify":{"verify_trust":true}}"#, "json")
                    .context("set trust mode default")?;
            }
            TrustMode::CustomPem { pem_path } => {
                let pem = std::fs::read_to_string(pem_path).with_context(|| {
                    format!("read custom trust PEM bundle {}", pem_path.display())
                })?;
                let cfg = json!({
                    "verify": { "verify_trust": true },
                    "trust": {
                        "trust_anchors": pem,
                        "private_anchors": pem
                    }
                });
                settings::load_settings_from_str(&cfg.to_string(), "json")
                    .context("set custom trust anchors")?;
            }
        }
        Ok(Self)
    }
}

impl Drop for SettingsGuard {
    fn drop(&mut self) {
        let _ = settings::reset_default_settings();
    }
}

pub fn inspect_path(path: &Path, opts: &InspectOptions) -> Result<C2paReport> {
    let input = build_input_meta(path)?;
    let _guard = SettingsGuard::apply(&opts.trust)?;

    match Reader::from_file(path) {
        Ok(reader) => inspect_reader(reader, input, opts),
        Err(c2pa::Error::JumbfNotFound) => Ok(report_no_credentials(input, opts)),
        Err(e) => Err(anyhow!(e)).with_context(|| format!("inspect {}", path.display())),
    }
}

pub fn inspect_reader(
    reader: Reader,
    input: InputMeta,
    opts: &InspectOptions,
) -> Result<C2paReport> {
    let mut warnings = Vec::new();
    let trust_mode = trust_mode_string(&opts.trust).to_string();
    if matches!(opts.trust, TrustMode::Off) {
        warnings.push("trust.disabled".to_string());
    }

    let Some(active_manifest) = reader.active_manifest() else {
        warnings.push("no.credentials".to_string());
        return Ok(C2paReport {
            tool: ToolInfo {
                name: TOOL_NAME.to_string(),
                schema_version: SCHEMA_VERSION,
            },
            input: InputSection {
                path: input.path,
                sha256: input.sha256,
                size_bytes: input.size_bytes,
                format_hint: input.format_hint,
            },
            credentials: CredentialsSection {
                present: false,
                active_manifest_label: None,
            },
            validation: ValidationSection {
                trust_mode,
                state: "unknown".to_string(),
                trusted: false,
                errors: Vec::new(),
                warnings,
            },
            signer: SignerSection {
                issuer: None,
                subject: None,
                organization: None,
                cert_sha256: None,
            },
            actions: Vec::new(),
            ingredients: Vec::new(),
        });
    };

    let mut state = map_validation_state(reader.validation_state());
    if matches!(opts.trust, TrustMode::Off) && state != "invalid" {
        state = "unknown".to_string();
    }
    let trusted = state == "trusted";
    if !trusted {
        warnings.push("credentials.untrusted".to_string());
    }

    let mut errors = Vec::new();
    if let Some(statuses) = reader.validation_status() {
        for s in statuses.iter().take(opts.max_errors) {
            errors.push(ValidationErr {
                code: s.code().to_string(),
                message: s.explanation().unwrap_or("validation issue").to_string(),
            });
        }
        if statuses.len() > opts.max_errors {
            warnings.push("truncated.errors".to_string());
        }
    }

    let mut actions = Vec::new();
    let actions_value = extract_actions_value(active_manifest);
    if let Some(items) = actions_value {
        for item in items.iter().take(opts.max_actions) {
            let action = item
                .get("action")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string();
            let when = item
                .get("when")
                .and_then(Value::as_str)
                .map(ToString::to_string);
            let software = extract_software(item);
            let parameters = item
                .get("parameters")
                .cloned()
                .unwrap_or_else(|| Value::Object(Map::new()));
            actions.push(ActionItem {
                action,
                when,
                software,
                parameters,
            });
        }
        if items.len() > opts.max_actions {
            warnings.push("truncated.actions".to_string());
        }
    }

    let mut ingredients = Vec::new();
    for ing in active_manifest
        .ingredients()
        .iter()
        .take(opts.max_ingredients)
    {
        let hash = ing.hash().map(|h| HashRef {
            alg: "sha256".to_string(),
            value: h.to_string(),
        });
        ingredients.push(IngredientItem {
            title: ing.title().map(ToString::to_string),
            relationship: Some(format!("{:?}", ing.relationship())),
            hash,
        });
    }
    if active_manifest.ingredients().len() > opts.max_ingredients {
        warnings.push("truncated.ingredients".to_string());
    }

    let mut signer = SignerSection {
        issuer: None,
        subject: None,
        organization: None,
        cert_sha256: None,
    };
    if let Some(sig) = active_manifest.signature_info() {
        signer.issuer = sig.issuer.clone();
        signer.cert_sha256 = Some(hex_sha256(sig.cert_chain().as_bytes()));
    }

    Ok(C2paReport {
        tool: ToolInfo {
            name: TOOL_NAME.to_string(),
            schema_version: SCHEMA_VERSION,
        },
        input: InputSection {
            path: input.path,
            sha256: input.sha256,
            size_bytes: input.size_bytes,
            format_hint: input.format_hint,
        },
        credentials: CredentialsSection {
            present: true,
            active_manifest_label: reader.active_label().map(ToString::to_string),
        },
        validation: ValidationSection {
            trust_mode,
            state,
            trusted,
            errors,
            warnings,
        },
        signer,
        actions,
        ingredients,
    })
}

pub fn parse_trust_mode(s: &str) -> Result<TrustMode> {
    match s {
        "off" => Ok(TrustMode::Off),
        "default" => Ok(TrustMode::Default),
        _ => {
            let Some(path) = s.strip_prefix("custom:") else {
                return Err(anyhow!(
                    "invalid trust mode: use off, default, or custom:<pem_path>"
                ));
            };
            if path.trim().is_empty() {
                return Err(anyhow!("custom trust mode requires pem path"));
            }
            Ok(TrustMode::CustomPem {
                pem_path: PathBuf::from(path),
            })
        }
    }
}

fn report_no_credentials(input: InputMeta, opts: &InspectOptions) -> C2paReport {
    let mut warnings = vec!["no.credentials".to_string()];
    if matches!(opts.trust, TrustMode::Off) {
        warnings.push("trust.disabled".to_string());
    }
    C2paReport {
        tool: ToolInfo {
            name: TOOL_NAME.to_string(),
            schema_version: SCHEMA_VERSION,
        },
        input: InputSection {
            path: input.path,
            sha256: input.sha256,
            size_bytes: input.size_bytes,
            format_hint: input.format_hint,
        },
        credentials: CredentialsSection {
            present: false,
            active_manifest_label: None,
        },
        validation: ValidationSection {
            trust_mode: trust_mode_string(&opts.trust).to_string(),
            state: "unknown".to_string(),
            trusted: false,
            errors: Vec::new(),
            warnings,
        },
        signer: SignerSection {
            issuer: None,
            subject: None,
            organization: None,
            cert_sha256: None,
        },
        actions: Vec::new(),
        ingredients: Vec::new(),
    }
}

fn trust_mode_string(mode: &TrustMode) -> &'static str {
    match mode {
        TrustMode::Off => "off",
        TrustMode::Default => "default",
        TrustMode::CustomPem { .. } => "custom",
    }
}

fn map_validation_state(state: ValidationState) -> String {
    match state {
        ValidationState::Invalid => "invalid".to_string(),
        ValidationState::Valid => "valid".to_string(),
        ValidationState::Trusted => "trusted".to_string(),
    }
}

fn extract_actions_value(manifest: &c2pa::Manifest) -> Option<Vec<Value>> {
    let actions: Actions = manifest
        .find_assertion(Actions::LABEL)
        .or_else(|_| manifest.find_assertion("c2pa.actions.v2"))
        .ok()?;
    let v = serde_json::to_value(actions).ok()?;
    let arr = v.get("actions")?.as_array()?.clone();
    Some(arr)
}

fn extract_software(action: &Value) -> Option<String> {
    let software = action.get("softwareAgent")?;
    if let Some(s) = software.as_str() {
        return Some(s.to_string());
    }
    software
        .get("name")
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

fn build_input_meta(path: &Path) -> Result<InputMeta> {
    let (sha256, size_bytes) = sha256_file(path)?;
    let format_hint = c2pa::format_from_path(path);
    Ok(InputMeta {
        path: path.to_string_lossy().to_string(),
        sha256,
        size_bytes,
        format_hint,
    })
}

fn sha256_file(path: &Path) -> Result<(String, u64)> {
    let mut f = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    let mut total: u64 = 0;
    loop {
        let n = f
            .read(&mut buf)
            .with_context(|| format!("read {}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((hex::encode(hasher.finalize()), total))
}

fn hex_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_trust_mode_works() {
        assert!(matches!(parse_trust_mode("off").unwrap(), TrustMode::Off));
        assert!(matches!(
            parse_trust_mode("default").unwrap(),
            TrustMode::Default
        ));
        assert!(matches!(
            parse_trust_mode("custom:ca.pem").unwrap(),
            TrustMode::CustomPem { .. }
        ));
    }
}
