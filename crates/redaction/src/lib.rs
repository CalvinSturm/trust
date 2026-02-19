use std::path::Path;

use anyhow::{Context, Result};
use regex::Regex;
use serde::Deserialize;
use serde_json::Value;

const MAX_STR_OUTPUT: usize = 32_768;
const MAX_JSON_STRING_BYTES: usize = 8_192;
const MAX_JSON_KEYS: usize = 512;
const MAX_JSON_ARRAY_ITEMS: usize = 512;

#[derive(Debug, Clone)]
pub struct Redactor {
    patterns: Vec<CompiledPattern>,
}

#[derive(Debug, Clone)]
struct CompiledPattern {
    replacement: String,
    regex: Regex,
}

#[derive(Debug, Deserialize)]
struct RedactionConfig {
    patterns: Vec<PatternConfig>,
}

#[derive(Debug, Deserialize)]
struct PatternConfig {
    #[allow(dead_code)]
    name: String,
    regex: String,
    replacement: String,
}

impl Redactor {
    pub fn new_default() -> Self {
        Self {
            patterns: vec![
                compiled("sk-[A-Za-z0-9]{20,}", "sk-REDACTED"),
                compiled(
                    "eyJ[A-Za-z0-9_-]+?\\.[A-Za-z0-9_-]+?\\.[A-Za-z0-9_-]+",
                    "JWT-REDACTED",
                ),
                compiled(
                    "-----BEGIN [^-]+-----[\\s\\S]*?-----END [^-]+-----",
                    "PEM-REDACTED",
                ),
                compiled(
                    "(?i)(api_key|token|secret|password)\\s*[:=]\\s*[\"']?[^\"'\\s]{6,}",
                    "$1=REDACTED",
                ),
            ],
        }
    }

    pub fn from_yaml(path: &Path) -> Result<Self> {
        let txt = std::fs::read_to_string(path)
            .with_context(|| format!("read redaction config {}", path.display()))?;
        let cfg = serde_yaml::from_str::<RedactionConfig>(&txt)
            .with_context(|| format!("parse redaction config {}", path.display()))?;
        let mut patterns = Vec::with_capacity(cfg.patterns.len());
        for p in cfg.patterns {
            let regex = Regex::new(&p.regex)
                .with_context(|| format!("invalid redaction regex {}", p.regex))?;
            patterns.push(CompiledPattern {
                replacement: p.replacement,
                regex,
            });
        }
        Ok(Self { patterns })
    }

    pub fn redact_str(&self, s: &str) -> String {
        let mut out = s.to_string();
        for p in &self.patterns {
            out = p
                .regex
                .replace_all(&out, p.replacement.as_str())
                .into_owned();
            if out.len() > MAX_STR_OUTPUT {
                out.truncate(MAX_STR_OUTPUT);
                out.push_str("...");
                break;
            }
        }
        if out.len() > MAX_STR_OUTPUT {
            out.truncate(MAX_STR_OUTPUT);
            out.push_str("...");
        }
        out
    }

    pub fn redact_json(&self, v: &Value) -> Value {
        self.redact_json_inner(v, 0)
    }

    fn redact_json_inner(&self, v: &Value, depth: usize) -> Value {
        if depth > 32 {
            return Value::String("<truncated-depth>".to_string());
        }

        match v {
            Value::String(s) => {
                let mut out = self.redact_str(s);
                if out.len() > MAX_JSON_STRING_BYTES {
                    out.truncate(MAX_JSON_STRING_BYTES);
                    out.push_str("...");
                }
                Value::String(out)
            }
            Value::Array(arr) => Value::Array(
                arr.iter()
                    .take(MAX_JSON_ARRAY_ITEMS)
                    .map(|x| self.redact_json_inner(x, depth + 1))
                    .collect(),
            ),
            Value::Object(map) => {
                let mut out = serde_json::Map::new();
                for (k, val) in map.iter().take(MAX_JSON_KEYS) {
                    out.insert(k.clone(), self.redact_json_inner(val, depth + 1));
                }
                Value::Object(out)
            }
            _ => v.clone(),
        }
    }
}

fn compiled(regex: &str, replacement: &str) -> CompiledPattern {
    CompiledPattern {
        regex: Regex::new(regex).expect("valid built-in regex"),
        replacement: replacement.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn defaults_redact_known_tokens() {
        let r = Redactor::new_default();
        let s = "token=abc123456 and sk-abcdefghijklmnopqrstuvwxyz123";
        let out = r.redact_str(s);
        assert!(out.contains("token=REDACTED"));
        assert!(out.contains("sk-REDACTED"));
    }

    #[test]
    fn redact_json_walks_nested_values() {
        let r = Redactor::new_default();
        let v = json!({"x":"password=supersecret","arr":["eyJabc.def.ghi"]});
        let out = r.redact_json(&v);
        assert!(out.to_string().contains("REDACTED"));
    }
}
