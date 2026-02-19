use anyhow::{Context, Result};
use globset::{Glob, GlobMatcher};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny,
    RequireApproval,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Policy {
    pub protocol_version: String,
    pub defaults: Defaults,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Defaults {
    pub decision: Decision,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    #[serde(rename = "match")]
    pub matcher: Match,
    pub decision: Decision,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Match {
    pub mcp_method: Option<String>,
    pub tool: Option<String>,
    pub args: Option<MatchArgs>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MatchArgs {
    pub view: Option<String>,
    pub path_glob: Option<String>,
}

pub fn parse_policy(yaml: &str) -> Result<Policy> {
    serde_yaml::from_str::<Policy>(yaml).context("parse policy yaml")
}

pub fn evaluate(policy: &Policy, method: &str, params: &Value) -> Decision {
    for rule in &policy.rules {
        if matches_rule(&rule.matcher, method, params) {
            return rule.decision.clone();
        }
    }
    policy.defaults.decision.clone()
}

fn matches_rule(m: &Match, method: &str, params: &Value) -> bool {
    if let Some(want_method) = &m.mcp_method {
        if want_method != method {
            return false;
        }
    }

    if let Some(want_tool) = &m.tool {
        let got_tool = params.get("name").and_then(Value::as_str);
        if got_tool != Some(want_tool.as_str()) {
            return false;
        }
    }

    if let Some(args_match) = &m.args {
        let args = params
            .get("arguments")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();

        if let Some(view) = &args_match.view {
            if args.get("view").and_then(Value::as_str) != Some(view.as_str()) {
                return false;
            }
        }

        if let Some(path_glob) = &args_match.path_glob {
            let path = args.get("path").and_then(Value::as_str).unwrap_or_default();
            if !glob_matches(path_glob, path) {
                return false;
            }
        }
    }

    true
}

fn glob_matches(pattern: &str, path: &str) -> bool {
    let matcher = compile_glob(pattern);
    matcher.is_match(path) || matcher.is_match(&format!("x/{path}"))
}

fn compile_glob(pattern: &str) -> GlobMatcher {
    Glob::new(pattern)
        .unwrap_or_else(|_| Glob::new("*").expect("fallback glob"))
        .compile_matcher()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_glob_matches_dotenv() {
        assert!(glob_matches("**/.env", ".env"));
    }
}
