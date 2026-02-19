use std::collections::{BTreeMap, HashSet};

use anyhow::{anyhow, Context, Result};
use globset::{Glob, GlobMatcher};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

const MAX_DIAGNOSTICS: usize = 200;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
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
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub priority: Option<i64>,
    #[serde(default)]
    pub hard: bool,
    #[serde(rename = "match")]
    pub matcher: Match,
    #[serde(default)]
    pub limit: Option<RateLimitConfig>,
    pub decision: Decision,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Match {
    pub client_id: Option<String>,
    pub auth_verified: Option<bool>,
    pub token_key_id: Option<String>,
    pub mcp_method: Option<String>,
    pub mcp_method_glob: Option<String>,
    pub tool: Option<String>,
    pub tool_glob: Option<String>,
    pub args: Option<BTreeMap<String, ArgMatcher>>,
    pub not: Option<Box<Match>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ArgMatcher {
    Ops(ArgOps),
    Scalar(Value),
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ArgOps {
    pub exact: Option<Value>,
    pub glob: Option<String>,
    pub regex: Option<String>,
    pub contains: Option<String>,
    pub range: Option<RangeSpec>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RangeSpec {
    pub min: Option<f64>,
    pub max: Option<f64>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RateLimitConfig {
    pub per_client: Option<TokenBucketSpec>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TokenBucketSpec {
    pub capacity: f64,
    pub refill_per_sec: f64,
}

#[derive(Debug, Clone, Default)]
pub struct RequestContext {
    pub client_id: Option<String>,
    pub auth_verified: Option<bool>,
    pub token_key_id: Option<String>,
}

pub type Request = PolicyRequest;
pub type ContextMatch = RequestContext;

#[derive(Debug, Clone)]
pub struct PolicyRequest {
    pub mcp_method: String,
    pub tool: Option<String>,
    pub args: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct Reason {
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct EvalResult {
    pub decision: Decision,
    pub matched: bool,
    pub matched_rule_id: Option<String>,
    pub matched_rule_index: Option<usize>,
    pub reasons: Vec<Reason>,
    pub rate_limit: Option<TokenBucketSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Error,
    Warning,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diagnostic {
    pub severity: Severity,
    pub code: String,
    pub message: String,
    pub rule_id: Option<String>,
    pub rule_index: Option<usize>,
    pub path: Option<String>,
    pub hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LintSummary {
    pub rule_count: usize,
    pub error_count: usize,
    pub warning_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LintReport {
    pub ok: bool,
    pub errors: Vec<Diagnostic>,
    pub warnings: Vec<Diagnostic>,
    pub summary: LintSummary,
}

#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    default_decision: Decision,
    rules: Vec<CompiledRule>,
}

#[derive(Debug, Clone)]
struct CompiledRule {
    id: Option<String>,
    index: usize,
    priority: i64,
    hard: bool,
    decision: Decision,
    limit: Option<TokenBucketSpec>,
    matcher: CompiledMatch,
}

#[derive(Debug, Clone)]
struct CGlob {
    matcher: GlobMatcher,
}

#[derive(Debug, Clone)]
struct CRegex {
    regex: Regex,
}

#[derive(Debug, Clone)]
enum CArg {
    Exact(Value),
    Glob(CGlob),
    Regex(CRegex),
    Contains(String),
    Range { min: Option<f64>, max: Option<f64> },
}

#[derive(Debug, Clone)]
struct CompiledMatch {
    client_id: Option<String>,
    auth_verified: Option<bool>,
    token_key_id: Option<String>,
    mcp_method: Option<String>,
    mcp_method_glob: Option<CGlob>,
    tool: Option<String>,
    tool_glob: Option<CGlob>,
    args: BTreeMap<String, Vec<CArg>>,
    not: Option<Box<CompiledMatch>>,
}

pub fn parse_policy(yaml: &str) -> Result<Policy> {
    serde_yaml::from_str::<Policy>(yaml).context("parse policy yaml")
}

impl Policy {
    pub fn compile(&self) -> Result<CompiledPolicy> {
        compile_policy(self)
    }

    pub fn evaluate(&self, method: &str, params: &Value) -> Decision {
        let req = request_from_params(method, params);
        self.evaluate_with_context(&req, &RequestContext::default())
            .decision
    }

    pub fn evaluate_with_context(&self, req: &Request, ctx: &ContextMatch) -> EvalResult {
        match self.compile() {
            Ok(c) => c.evaluate_with_context(req, ctx),
            Err(e) => EvalResult {
                decision: self.defaults.decision.clone(),
                matched: false,
                matched_rule_id: None,
                matched_rule_index: None,
                reasons: vec![Reason {
                    message: format!("policy compile failed: {e}"),
                }],
                rate_limit: None,
            },
        }
    }
}

impl CompiledPolicy {
    pub fn evaluate_with_context(&self, req: &Request, ctx: &ContextMatch) -> EvalResult {
        let mut matched: Vec<&CompiledRule> = Vec::new();
        for rule in &self.rules {
            if matches_rule(&rule.matcher, req, ctx) {
                matched.push(rule);
            }
        }
        if matched.is_empty() {
            return EvalResult {
                decision: self.default_decision.clone(),
                matched: false,
                matched_rule_id: None,
                matched_rule_index: None,
                reasons: vec![Reason {
                    message: "no rule matched; default applied".to_string(),
                }],
                rate_limit: None,
            };
        }
        let hard = matched
            .iter()
            .filter(|r| r.hard && r.decision == Decision::Deny)
            .max_by_key(|r| (r.priority, -(r.index as i64)));
        let chosen = if let Some(r) = hard {
            *r
        } else {
            *matched
                .iter()
                .max_by_key(|r| (r.priority, -(r.index as i64)))
                .expect("matched non-empty")
        };
        let mut reasons = vec![Reason {
            message: format!(
                "matched rule index={} priority={}",
                chosen.index, chosen.priority
            ),
        }];
        if chosen.hard && chosen.decision == Decision::Deny {
            reasons.push(Reason {
                message: "hard deny takes precedence".to_string(),
            });
        }
        EvalResult {
            decision: chosen.decision.clone(),
            matched: true,
            matched_rule_id: chosen.id.clone(),
            matched_rule_index: Some(chosen.index),
            reasons,
            rate_limit: chosen.limit.clone(),
        }
    }
}

pub fn evaluate(policy: &Policy, method: &str, params: &Value) -> Decision {
    policy.evaluate(method, params)
}

pub fn request_from_params(method: &str, params: &Value) -> PolicyRequest {
    PolicyRequest {
        mcp_method: method.to_string(),
        tool: params
            .get("name")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        args: params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| Value::Object(Default::default())),
    }
}

pub fn evaluate_with_context(policy: &Policy, req: &Request, ctx: &ContextMatch) -> EvalResult {
    policy.evaluate_with_context(req, ctx)
}

pub fn lint_policy(policy: &Policy) -> LintReport {
    let mut all = Vec::<Diagnostic>::new();
    let mut ids = HashSet::new();

    for (idx, rule) in policy.rules.iter().enumerate() {
        if let Some(id) = &rule.id {
            if !ids.insert(id.clone()) {
                push_diag(
                    &mut all,
                    Diagnostic {
                        severity: Severity::Error,
                        code: "rule.duplicate_id".to_string(),
                        message: format!("duplicate rule id '{id}'"),
                        rule_id: Some(id.clone()),
                        rule_index: Some(idx),
                        path: Some(format!("rules[{idx}].id")),
                        hint: Some("use unique ids".to_string()),
                    },
                );
            }
        } else {
            push_diag(
                &mut all,
                Diagnostic {
                    severity: Severity::Warning,
                    code: "rule.missing_id".to_string(),
                    message: "rule id is recommended".to_string(),
                    rule_id: None,
                    rule_index: Some(idx),
                    path: Some(format!("rules[{idx}]")),
                    hint: Some("add id for stable explain/audit".to_string()),
                },
            );
        }

        lint_match(rule, idx, &rule.matcher, "match", &mut all);
        lint_unreachable(rule, idx, &mut all);

        if let Some(limit) = &rule.limit {
            if let Some(pc) = &limit.per_client {
                if pc.capacity <= 0.0 || pc.refill_per_sec <= 0.0 {
                    push_diag(
                        &mut all,
                        diag_error(
                            "rule.limit_invalid",
                            "per_client capacity/refill_per_sec must be > 0".to_string(),
                            rule,
                            idx,
                            Some(format!("rules[{idx}].limit.per_client")),
                        ),
                    );
                }
            }
        }

        if matches!(rule.decision, Decision::Allow | Decision::RequireApproval)
            && matcher_is_empty(&rule.matcher)
        {
            push_diag(
                &mut all,
                diag_error(
                    "rule.allow_all",
                    "allow/require_approval rule has no constraints".to_string(),
                    rule,
                    idx,
                    Some(format!("rules[{idx}].match")),
                ),
            );
        }
    }

    lint_shadow(policy, &mut all);
    lint_ambiguous(policy, &mut all);

    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    for d in all {
        match d.severity {
            Severity::Error => errors.push(d),
            Severity::Warning => warnings.push(d),
        }
    }
    LintReport {
        ok: errors.is_empty(),
        summary: LintSummary {
            rule_count: policy.rules.len(),
            error_count: errors.len(),
            warning_count: warnings.len(),
        },
        errors,
        warnings,
    }
}

pub fn compile_and_lint(policy: &Policy) -> Result<(CompiledPolicy, LintReport)> {
    Ok((policy.compile()?, lint_policy(policy)))
}

fn compile_policy(policy: &Policy) -> Result<CompiledPolicy> {
    let mut rules = Vec::with_capacity(policy.rules.len());
    for (idx, rule) in policy.rules.iter().enumerate() {
        rules.push(CompiledRule {
            id: rule.id.clone(),
            index: idx,
            priority: rule.priority.unwrap_or(0),
            hard: rule.hard,
            decision: rule.decision.clone(),
            limit: rule.limit.as_ref().and_then(|l| l.per_client.clone()),
            matcher: compile_match(&rule.matcher, idx, rule.id.as_deref(), "match")?,
        });
        if let Some(pc) = rule.limit.as_ref().and_then(|l| l.per_client.as_ref()) {
            if pc.capacity <= 0.0 || pc.refill_per_sec <= 0.0 {
                return Err(anyhow!(
                    "compile error at rules[{idx}].limit.per_client: capacity/refill_per_sec must be > 0"
                ));
            }
        }
    }
    Ok(CompiledPolicy {
        default_decision: policy.defaults.decision.clone(),
        rules,
    })
}

fn compile_match(m: &Match, idx: usize, rid: Option<&str>, path: &str) -> Result<CompiledMatch> {
    let mcp_method_glob = if let Some(p) = &m.mcp_method_glob {
        Some(CGlob {
            matcher: compile_glob(p).map_err(|e| {
                anyhow!("compile error at rules[{idx}].{path}.mcp_method_glob ({rid:?}): {e}")
            })?,
        })
    } else {
        None
    };
    let tool_glob = if let Some(p) = &m.tool_glob {
        Some(CGlob {
            matcher: compile_glob(p).map_err(|e| {
                anyhow!("compile error at rules[{idx}].{path}.tool_glob ({rid:?}): {e}")
            })?,
        })
    } else {
        None
    };
    let mut args = BTreeMap::<String, Vec<CArg>>::new();
    if let Some(spec) = &m.args {
        for (k, v) in spec {
            if k == "path_glob" {
                let Some(p) = scalar_pattern(v) else {
                    return Err(anyhow!(
                        "compile error at rules[{idx}].{path}.args.path_glob: expected string"
                    ));
                };
                args.entry("path".to_string())
                    .or_default()
                    .push(CArg::Glob(CGlob {
                        matcher: compile_glob(&p)?,
                    }));
                continue;
            }
            args.entry(k.clone()).or_default().extend(compile_arg(
                v,
                idx,
                rid,
                &format!("{path}.args.{k}"),
            )?);
        }
    }
    let not = if let Some(n) = &m.not {
        Some(Box::new(compile_match(
            n,
            idx,
            rid,
            &format!("{path}.not"),
        )?))
    } else {
        None
    };
    Ok(CompiledMatch {
        client_id: m.client_id.clone(),
        auth_verified: m.auth_verified,
        token_key_id: m.token_key_id.clone(),
        mcp_method: m.mcp_method.clone(),
        mcp_method_glob,
        tool: m.tool.clone(),
        tool_glob,
        args,
        not,
    })
}

fn compile_arg(spec: &ArgMatcher, idx: usize, rid: Option<&str>, path: &str) -> Result<Vec<CArg>> {
    let mut out = Vec::new();
    match spec {
        ArgMatcher::Scalar(v) => out.push(CArg::Exact(v.clone())),
        ArgMatcher::Ops(ops) => {
            if let Some(v) = &ops.exact {
                out.push(CArg::Exact(v.clone()));
            }
            if let Some(g) = &ops.glob {
                out.push(CArg::Glob(CGlob {
                    matcher: compile_glob(g).map_err(|e| {
                        anyhow!("compile error at rules[{idx}].{path} ({rid:?}): {e}")
                    })?,
                }));
            }
            if let Some(r) = &ops.regex {
                out.push(CArg::Regex(CRegex {
                    regex: Regex::new(r).map_err(|e| {
                        anyhow!("compile error at rules[{idx}].{path}.regex ({rid:?}): {e}")
                    })?,
                }));
            }
            if let Some(c) = &ops.contains {
                out.push(CArg::Contains(c.clone()));
            }
            if let Some(range) = &ops.range {
                if let (Some(min), Some(max)) = (range.min, range.max) {
                    if min > max {
                        return Err(anyhow!(
                            "compile error at rules[{idx}].{path}.range ({rid:?}): min > max"
                        ));
                    }
                }
                out.push(CArg::Range {
                    min: range.min,
                    max: range.max,
                });
            }
        }
    }
    Ok(out)
}

fn matches_rule(m: &CompiledMatch, req: &Request, ctx: &ContextMatch) -> bool {
    if let Some(c) = &m.client_id {
        if ctx.client_id.as_deref() != Some(c.as_str()) {
            return false;
        }
    }
    if let Some(v) = m.auth_verified {
        if ctx.auth_verified != Some(v) {
            return false;
        }
    }
    if let Some(k) = &m.token_key_id {
        if ctx.token_key_id.as_deref() != Some(k.as_str()) {
            return false;
        }
    }
    if let Some(mm) = &m.mcp_method {
        if mm != &req.mcp_method {
            return false;
        }
    }
    if let Some(g) = &m.mcp_method_glob {
        if !matches_glob(g, &req.mcp_method) {
            return false;
        }
    }
    if let Some(t) = &m.tool {
        if req.tool.as_deref() != Some(t.as_str()) {
            return false;
        }
    }
    if let Some(g) = &m.tool_glob {
        let Some(t) = req.tool.as_deref() else {
            return false;
        };
        if !matches_glob(g, t) {
            return false;
        }
    }
    for (k, cons) in &m.args {
        let target = req.args.get(k).cloned().unwrap_or(Value::Null);
        for c in cons {
            if !matches_arg(c, &target) {
                return false;
            }
        }
    }
    if let Some(n) = &m.not {
        if matches_rule(n, req, ctx) {
            return false;
        }
    }
    true
}

fn matches_arg(c: &CArg, target: &Value) -> bool {
    match c {
        CArg::Exact(v) => v == target,
        CArg::Glob(g) => target.as_str().map(|s| matches_glob(g, s)).unwrap_or(false),
        CArg::Regex(r) => target
            .as_str()
            .map(|s| r.regex.is_match(s))
            .unwrap_or(false),
        CArg::Contains(n) => target.as_str().map(|s| s.contains(n)).unwrap_or(false),
        CArg::Range { min, max } => {
            let Some(n) = target.as_f64() else {
                return false;
            };
            if let Some(lo) = min {
                if n < *lo {
                    return false;
                }
            }
            if let Some(hi) = max {
                if n > *hi {
                    return false;
                }
            }
            true
        }
    }
}

fn compile_glob(pattern: &str) -> Result<GlobMatcher> {
    Ok(Glob::new(pattern)?.compile_matcher())
}

fn matches_glob(g: &CGlob, value: &str) -> bool {
    g.matcher.is_match(value) || g.matcher.is_match(format!("x/{value}"))
}

fn glob_matches(pattern: &str, value: &str) -> bool {
    match compile_glob(pattern) {
        Ok(m) => m.is_match(value) || m.is_match(format!("x/{value}")),
        Err(_) => false,
    }
}

fn scalar_pattern(v: &ArgMatcher) -> Option<String> {
    match v {
        ArgMatcher::Scalar(v) => v.as_str().map(ToString::to_string),
        ArgMatcher::Ops(o) => o.glob.clone().or_else(|| {
            o.exact
                .as_ref()
                .and_then(Value::as_str)
                .map(ToString::to_string)
        }),
    }
}

fn lint_match(rule: &Rule, idx: usize, m: &Match, path: &str, out: &mut Vec<Diagnostic>) {
    if let Some(g) = &m.tool_glob {
        if compile_glob(g).is_err() {
            push_diag(
                out,
                diag_error(
                    "rule.invalid_glob",
                    format!("invalid tool_glob '{g}'"),
                    rule,
                    idx,
                    Some(format!("{path}.tool_glob")),
                ),
            );
        }
    }
    if let Some(g) = &m.mcp_method_glob {
        if compile_glob(g).is_err() {
            push_diag(
                out,
                diag_error(
                    "rule.invalid_glob",
                    format!("invalid mcp_method_glob '{g}'"),
                    rule,
                    idx,
                    Some(format!("{path}.mcp_method_glob")),
                ),
            );
        }
    }
    if let Some(args) = &m.args {
        for (k, v) in args {
            if k == "path_glob" && scalar_pattern(v).is_none() {
                push_diag(
                    out,
                    diag_error(
                        "rule.invalid_glob",
                        "path_glob expects a string".to_string(),
                        rule,
                        idx,
                        Some(format!("{path}.args.path_glob")),
                    ),
                );
            }
            if let ArgMatcher::Ops(o) = v {
                if let Some(g) = &o.glob {
                    if compile_glob(g).is_err() {
                        push_diag(
                            out,
                            diag_error(
                                "rule.invalid_glob",
                                format!("invalid glob '{g}'"),
                                rule,
                                idx,
                                Some(format!("{path}.args.{k}.glob")),
                            ),
                        );
                    }
                }
                if let Some(r) = &o.regex {
                    if Regex::new(r).is_err() {
                        push_diag(
                            out,
                            diag_error(
                                "rule.invalid_regex",
                                format!("invalid regex '{r}'"),
                                rule,
                                idx,
                                Some(format!("{path}.args.{k}.regex")),
                            ),
                        );
                    }
                }
                if let Some(range) = &o.range {
                    if let (Some(min), Some(max)) = (range.min, range.max) {
                        if min > max {
                            push_diag(
                                out,
                                diag_error(
                                    "rule.invalid_range",
                                    "range min > max".to_string(),
                                    rule,
                                    idx,
                                    Some(format!("{path}.args.{k}.range")),
                                ),
                            );
                        }
                    }
                }
            }
        }
    }
    if let Some(n) = &m.not {
        lint_match(rule, idx, n, &format!("{path}.not"), out);
    }
}

fn lint_unreachable(rule: &Rule, idx: usize, out: &mut Vec<Diagnostic>) {
    if let (Some(t), Some(g)) = (&rule.matcher.tool, &rule.matcher.tool_glob) {
        if !glob_matches(g, t) {
            push_diag(
                out,
                diag_warn(
                    "rule.unreachable",
                    "tool exact does not match tool_glob".to_string(),
                    rule,
                    idx,
                    Some(format!("rules[{idx}].match")),
                ),
            );
        }
    }
    if let (Some(m), Some(g)) = (&rule.matcher.mcp_method, &rule.matcher.mcp_method_glob) {
        if !glob_matches(g, m) {
            push_diag(
                out,
                diag_warn(
                    "rule.unreachable",
                    "mcp_method exact does not match mcp_method_glob".to_string(),
                    rule,
                    idx,
                    Some(format!("rules[{idx}].match")),
                ),
            );
        }
    }
}

fn matcher_is_empty(m: &Match) -> bool {
    m.client_id.is_none()
        && m.auth_verified.is_none()
        && m.token_key_id.is_none()
        && m.mcp_method.is_none()
        && m.mcp_method_glob.is_none()
        && m.tool.is_none()
        && m.tool_glob.is_none()
        && m.args.as_ref().map(|a| a.is_empty()).unwrap_or(true)
        && m.not.is_none()
}

fn lint_shadow(policy: &Policy, out: &mut Vec<Diagnostic>) {
    for (j, r) in policy.rules.iter().enumerate() {
        if !matches!(r.decision, Decision::Allow | Decision::RequireApproval) {
            continue;
        }
        for i in 0..j {
            let p = &policy.rules[i];
            if p.hard
                && p.decision == Decision::Deny
                && p.matcher.args.is_none()
                && p.matcher.not.is_none()
                && scope_overlap(&p.matcher, &r.matcher)
            {
                push_diag(
                    out,
                    diag_warn(
                        "rule.shadowed",
                        "earlier hard deny likely shadows this rule".to_string(),
                        r,
                        j,
                        Some(format!("rules[{j}]")),
                    ),
                );
                break;
            }
        }
    }
}

fn lint_ambiguous(policy: &Policy, out: &mut Vec<Diagnostic>) {
    for i in 0..policy.rules.len() {
        for j in (i + 1)..policy.rules.len() {
            let a = &policy.rules[i];
            let b = &policy.rules[j];
            if !scope_overlap(&a.matcher, &b.matcher) {
                continue;
            }
            if (a.hard && a.decision == Decision::Deny) || (b.hard && b.decision == Decision::Deny)
            {
                push_diag(
                    out,
                    diag_warn(
                        "rule.overlap_hard_deny",
                        "hard deny overlaps with another rule; deny wins".to_string(),
                        b,
                        j,
                        Some(format!("rules[{j}]")),
                    ),
                );
            }
            if a.priority == b.priority && a.decision != b.decision {
                push_diag(
                    out,
                    diag_warn(
                        "rule.overlap_same_priority",
                        "overlapping rules with same priority and different decisions".to_string(),
                        b,
                        j,
                        Some(format!("rules[{j}]")),
                    ),
                );
            }
        }
    }
}

fn scope_overlap(a: &Match, b: &Match) -> bool {
    let tool_ok = selector_overlap(&a.tool, &a.tool_glob, &b.tool, &b.tool_glob);
    let method_ok = selector_overlap(
        &a.mcp_method,
        &a.mcp_method_glob,
        &b.mcp_method,
        &b.mcp_method_glob,
    );
    tool_ok && method_ok
}

fn selector_overlap(
    a_exact: &Option<String>,
    a_glob: &Option<String>,
    b_exact: &Option<String>,
    b_glob: &Option<String>,
) -> bool {
    match (a_exact, a_glob, b_exact, b_glob) {
        (Some(x), _, Some(y), _) => x == y,
        (Some(x), _, _, Some(g)) | (_, Some(g), Some(x), _) => glob_matches(g, x),
        (None, None, _, _) | (_, _, None, None) => true,
        (_, Some(g1), _, Some(g2)) => g1 == g2,
    }
}

fn diag_error(
    code: &str,
    message: String,
    rule: &Rule,
    idx: usize,
    path: Option<String>,
) -> Diagnostic {
    Diagnostic {
        severity: Severity::Error,
        code: code.to_string(),
        message,
        rule_id: rule.id.clone(),
        rule_index: Some(idx),
        path,
        hint: None,
    }
}

fn diag_warn(
    code: &str,
    message: String,
    rule: &Rule,
    idx: usize,
    path: Option<String>,
) -> Diagnostic {
    Diagnostic {
        severity: Severity::Warning,
        code: code.to_string(),
        message,
        rule_id: rule.id.clone(),
        rule_index: Some(idx),
        path,
        hint: None,
    }
}

fn push_diag(diags: &mut Vec<Diagnostic>, diag: Diagnostic) {
    if diags.len() >= MAX_DIAGNOSTICS {
        if !diags.iter().any(|d| d.code == "lint.truncated") {
            diags.push(Diagnostic {
                severity: Severity::Warning,
                code: "lint.truncated".to_string(),
                message: "diagnostics truncated".to_string(),
                rule_id: None,
                rule_index: None,
                path: None,
                hint: None,
            });
        }
        return;
    }
    diags.push(diag);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(tool: &str, args: Value) -> PolicyRequest {
        PolicyRequest {
            mcp_method: "tools/call".to_string(),
            tool: Some(tool.to_string()),
            args,
        }
    }

    #[test]
    fn compile_and_eval_preserves_behavior() {
        let policy = parse_policy(
            r#"
protocol_version: "2025-06-18"
defaults:
  decision: deny
rules:
  - id: r1
    match:
      tool_glob: "files.*"
      args:
        path:
          regex: ".*\\.txt$"
    decision: allow
"#,
        )
        .unwrap();
        let c = policy.compile().unwrap();
        assert_eq!(
            c.evaluate_with_context(
                &req("files.search", serde_json::json!({"path":"a.txt"})),
                &RequestContext::default()
            )
            .decision,
            Decision::Allow
        );
    }

    #[test]
    fn hard_deny_and_tie_breaking() {
        let policy = parse_policy(
            r#"
protocol_version: "2025-06-18"
defaults:
  decision: deny
rules:
  - id: a1
    priority: 10
    match: { tool: "files.read" }
    decision: allow
  - id: d1
    hard: true
    match:
      tool: "files.read"
      args:
        path: { glob: "**/.env" }
    decision: deny
"#,
        )
        .unwrap();
        let out = evaluate_with_context(
            &policy,
            &req("files.read", serde_json::json!({"path":".env"})),
            &RequestContext::default(),
        );
        assert_eq!(out.decision, Decision::Deny);
        assert_eq!(out.matched_rule_id.as_deref(), Some("d1"));
    }

    #[test]
    fn backwards_compat_path_glob() {
        let policy = parse_policy(
            r#"
protocol_version: "2025-06-18"
defaults: { decision: deny }
rules:
  - match:
      tool: "files.read"
      args:
        path_glob: "**/.env"
    decision: deny
"#,
        )
        .unwrap();
        let out = evaluate_with_context(
            &policy,
            &req("files.read", serde_json::json!({"path":".env"})),
            &RequestContext::default(),
        );
        assert_eq!(out.decision, Decision::Deny);
    }

    #[test]
    fn lint_catches_invalid_and_duplicate() {
        let policy = parse_policy(
            r#"
protocol_version: "2025-06-18"
defaults: { decision: deny }
rules:
  - id: dup
    match:
      tool: "files.search"
      args:
        query: { regex: "[" }
    decision: allow
  - id: dup
    match:
      tool: "files.search"
      args:
        n: { range: { min: 10, max: 1 } }
    decision: allow
"#,
        )
        .unwrap();
        let lint = lint_policy(&policy);
        assert!(!lint.ok);
        assert!(lint.errors.iter().any(|d| d.code == "rule.invalid_regex"));
        assert!(lint.errors.iter().any(|d| d.code == "rule.invalid_range"));
        assert!(lint.errors.iter().any(|d| d.code == "rule.duplicate_id"));
    }

    #[test]
    fn lint_shadow_warning() {
        let policy = parse_policy(
            r#"
protocol_version: "2025-06-18"
defaults: { decision: deny }
rules:
  - id: hd
    hard: true
    match: { tool: "views.query" }
    decision: deny
  - id: allow2
    match: { tool: "views.query" }
    decision: allow
"#,
        )
        .unwrap();
        let lint = lint_policy(&policy);
        assert!(lint.warnings.iter().any(|d| d.code == "rule.shadowed"));
    }
}
