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
    pub client_id: Option<String>,
    pub auth_verified: Option<bool>,
    pub token_key_id: Option<String>,
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
    evaluate_with_context(policy, method, params, &RequestContext::default())
}

#[derive(Debug, Clone, Default)]
pub struct RequestContext {
    pub client_id: Option<String>,
    pub auth_verified: Option<bool>,
    pub token_key_id: Option<String>,
}

pub fn evaluate_with_context(
    policy: &Policy,
    method: &str,
    params: &Value,
    ctx: &RequestContext,
) -> Decision {
    for rule in &policy.rules {
        if matches_rule(&rule.matcher, method, params, ctx) {
            return rule.decision.clone();
        }
    }
    policy.defaults.decision.clone()
}

fn matches_rule(m: &Match, method: &str, params: &Value, ctx: &RequestContext) -> bool {
    if let Some(want_client) = &m.client_id {
        if ctx.client_id.as_deref() != Some(want_client.as_str()) {
            return false;
        }
    }

    if let Some(want_verified) = m.auth_verified {
        if ctx.auth_verified != Some(want_verified) {
            return false;
        }
    }

    if let Some(want_key_id) = &m.token_key_id {
        if ctx.token_key_id.as_deref() != Some(want_key_id.as_str()) {
            return false;
        }
    }

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
    matcher.is_match(path) || matcher.is_match(format!("x/{path}"))
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

    #[test]
    fn client_id_and_auth_verified_match() {
        let policy = parse_policy(
            r#"
protocol_version: "2025-06-18"
defaults:
  decision: deny
rules:
  - match:
      client_id: "alice"
      auth_verified: true
      mcp_method: "tools/call"
      tool: "views.query"
    decision: allow
"#,
        )
        .unwrap();
        let params = serde_json::json!({"name":"views.query","arguments":{"view":"notes_recent"}});
        let allow = evaluate_with_context(
            &policy,
            "tools/call",
            &params,
            &RequestContext {
                client_id: Some("alice".to_string()),
                auth_verified: Some(true),
                token_key_id: None,
            },
        );
        assert_eq!(allow, Decision::Allow);
        let deny = evaluate_with_context(
            &policy,
            "tools/call",
            &params,
            &RequestContext {
                client_id: Some("bob".to_string()),
                auth_verified: Some(true),
                token_key_id: None,
            },
        );
        assert_eq!(deny, Decision::Deny);
    }

    #[test]
    fn backwards_compat_legacy_policy_still_works() {
        let policy = parse_policy(
            r#"
protocol_version: "2025-06-18"
defaults:
  decision: deny
rules:
  - match:
      mcp_method: "tools/call"
      tool: "views.query"
      args:
        view: "notes_recent"
    decision: allow
"#,
        )
        .unwrap();
        let params = serde_json::json!({"name":"views.query","arguments":{"view":"notes_recent"}});
        assert_eq!(evaluate(&policy, "tools/call", &params), Decision::Allow);
    }
}
