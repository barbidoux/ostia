//! The loader: size, then the Ed25519 signature over the exact bytes, then strict JSON, then the ranges of
//! `schemas/policy.schema.json`. Nothing is parsed before the signature verifies.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};

use super::{
    EngineRole, Indicator, KEY_BYTES, Limits, MAX_POLICY_BYTES, Policy, PolicyError, Refusal,
    SIGNATURE_BYTES,
};

const SCHEMA: &str = "ostia.policy.v1";
const MAX_VERSION_CHARS: usize = 64;
const MAX_ENGINE_ID_CHARS: usize = 64;

fn signature_invalid(detail: impl Into<String>) -> PolicyError {
    PolicyError {
        refusal: Refusal::SignatureInvalid,
        detail: detail.into(),
    }
}

fn invalid(detail: impl Into<String>) -> PolicyError {
    PolicyError {
        refusal: Refusal::Invalid,
        detail: detail.into(),
    }
}

/// Load a policy: check the size, verify the signature over the exact bytes, then parse and validate.
///
/// # Errors
/// [`PolicyError`] with [`Refusal::SignatureInvalid`] or [`Refusal::Invalid`].
pub fn load(policy: &[u8], signature: &[u8], trusted_key: &[u8]) -> Result<Policy, PolicyError> {
    if policy.len() > MAX_POLICY_BYTES {
        return Err(invalid(format!(
            "the policy is larger than {MAX_POLICY_BYTES} bytes"
        )));
    }
    verify(policy, signature, trusted_key)?;
    let Strict(value) = serde_json::from_slice(policy).map_err(|e| invalid(one_line(&e)))?;
    let file: PolicyFile = serde_json::from_value(value).map_err(|e| invalid(one_line(&e)))?;
    validate(file, Sha256::digest(policy).into())
}

fn one_line(error: &impl fmt::Display) -> String {
    error.to_string().replace(['\n', '\r'], " ")
}

fn verify(policy: &[u8], signature: &[u8], trusted_key: &[u8]) -> Result<(), PolicyError> {
    let signature: [u8; SIGNATURE_BYTES] = signature.try_into().map_err(|_| {
        signature_invalid(format!(
            "the signature has {} bytes, not {SIGNATURE_BYTES}",
            signature.len()
        ))
    })?;
    let key: [u8; KEY_BYTES] = trusted_key.try_into().map_err(|_| {
        signature_invalid(format!(
            "the trusted key has {} bytes, not {KEY_BYTES}",
            trusted_key.len()
        ))
    })?;
    let key = VerifyingKey::from_bytes(&key)
        .map_err(|_| signature_invalid("the trusted key is not a valid Ed25519 public key"))?;
    key.verify_strict(policy, &Signature::from_bytes(&signature))
        .map_err(|_| signature_invalid("the signature does not verify with the trusted key"))
}

/// A JSON value parsed with every object checked for duplicate keys (`serde_json` keeps the last one,
/// while a human reviewer reads the first).
struct Strict(Value);

impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(StrictVisitor).map(Strict)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("a number that is not finite"))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(Strict(item)) = seq.next_element()? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut object = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if object.contains_key(&key) {
                return Err(de::Error::custom(format!("duplicate key \"{key}\"")));
            }
            let Strict(value) = map.next_value()?;
            object.insert(key, value);
        }
        Ok(Value::Object(object))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    schema: String,
    version: String,
    engines: BTreeMap<String, EngineEntry>,
    rules: RulesFile,
    limits: LimitsFile,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EngineEntry {
    role: String,
    trusted_alone: Option<bool>,
    thresholds: Option<ThresholdsFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ThresholdsFile {
    low: f64,
    high: f64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RulesFile {
    #[serde(rename = "R1")]
    r1: R1File,
    #[serde(rename = "R2")]
    r2: R2File,
    #[serde(rename = "R6")]
    r6: R6File,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct R1File {
    risky_types: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct R2File {
    k: u32,
    critical_severity: u32,
}

/// An R6 indicator switch (`true`: enabled).
#[derive(Deserialize, Clone, Copy)]
#[serde(transparent)]
struct Flag(bool);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct R6File {
    double_extension: Flag,
    extension_mismatch: Flag,
    single_detection: Flag,
    suspicious_hint: Flag,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LimitsFile {
    max_depth: u32,
    max_ratio: u64,
    max_total_bytes: u64,
    max_entries: u64,
    max_path_length: u32,
    engine_timeout_seconds: u32,
}

fn validate(file: PolicyFile, sha256: [u8; 32]) -> Result<Policy, PolicyError> {
    if file.schema != SCHEMA {
        return Err(invalid(format!("schema must be \"{SCHEMA}\"")));
    }
    let version_chars = file.version.chars().count();
    if !(1..=MAX_VERSION_CHARS).contains(&version_chars) {
        return Err(invalid(format!(
            "version must have 1 to {MAX_VERSION_CHARS} characters"
        )));
    }
    let mut engines = BTreeMap::new();
    for (id, entry) in file.engines {
        let role = engine_role(&id, entry)?;
        engines.insert(id, role);
    }
    let mut risky_types = BTreeSet::new();
    for risky in file.rules.r1.risky_types {
        if !is_type_name(&risky) {
            return Err(invalid(format!(
                "risky type \"{risky}\" is not a type name"
            )));
        }
        if !risky_types.insert(risky.clone()) {
            return Err(invalid(format!("risky type \"{risky}\" is listed twice")));
        }
    }
    let r2 = file.rules.r2;
    if r2.k < 2 {
        return Err(invalid("rules.R2.k must be at least 2"));
    }
    if !(1..=4).contains(&r2.critical_severity) {
        return Err(invalid("rules.R2.critical_severity must be 1 to 4"));
    }
    let r6 = file.rules.r6;
    let r6: BTreeSet<Indicator> = [
        (r6.double_extension, Indicator::DoubleExtension),
        (r6.extension_mismatch, Indicator::ExtensionMismatch),
        (r6.single_detection, Indicator::SingleDetection),
        (r6.suspicious_hint, Indicator::SuspiciousHint),
    ]
    .into_iter()
    .filter_map(|(Flag(enabled), indicator)| enabled.then_some(indicator))
    .collect();
    Ok(Policy {
        version: file.version,
        sha256,
        engines,
        risky_types,
        k: u64::from(r2.k),
        critical_severity: r2.critical_severity,
        r6,
        limits: limits(&file.limits)?,
    })
}

fn engine_role(id: &str, entry: EngineEntry) -> Result<EngineRole, PolicyError> {
    if !is_engine_id(id) {
        return Err(invalid(format!("engine id \"{id}\" is not valid")));
    }
    match (entry.role.as_str(), entry.trusted_alone, entry.thresholds) {
        ("detector", Some(trusted_alone), None) => Ok(EngineRole::Detector { trusted_alone }),
        ("scorer", None, Some(ThresholdsFile { low, high })) => {
            if low > 0.0 && low < high && high <= 1.0 {
                Ok(EngineRole::Scorer { low, high })
            } else {
                Err(invalid(format!(
                    "engine \"{id}\": thresholds need 0 < low < high <= 1"
                )))
            }
        }
        ("reputation", None, None) => Ok(EngineRole::Reputation),
        ("heuristic", None, None) => Ok(EngineRole::Heuristic),
        (role, _, _) => Err(invalid(format!(
            "engine \"{id}\": role \"{role}\" with keys the contract does not allow"
        ))),
    }
}

fn limits(file: &LimitsFile) -> Result<Limits, PolicyError> {
    let checks = [
        ("max_depth", (1..=64).contains(&file.max_depth)),
        ("max_ratio", file.max_ratio >= 1),
        ("max_total_bytes", file.max_total_bytes >= 1),
        ("max_entries", file.max_entries >= 1),
        (
            "max_path_length",
            (1..=65_535).contains(&file.max_path_length),
        ),
        (
            "engine_timeout_seconds",
            (1..=3600).contains(&file.engine_timeout_seconds),
        ),
    ];
    if let Some((name, _)) = checks.iter().find(|(_, ok)| !ok) {
        return Err(invalid(format!("limits.{name} is out of range")));
    }
    Ok(Limits {
        max_depth: file.max_depth,
        max_ratio: file.max_ratio,
        max_total_bytes: file.max_total_bytes,
        max_entries: file.max_entries,
        max_path_length: file.max_path_length,
        engine_timeout_seconds: file.engine_timeout_seconds,
    })
}

/// `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`
fn is_engine_id(id: &str) -> bool {
    let mut chars = id.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && id.chars().count() <= MAX_ENGINE_ID_CHARS
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// `^[a-z0-9][a-z0-9_.-]*$`
fn is_type_name(name: &str) -> bool {
    let lower = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit();
    let mut chars = name.chars();
    chars.next().is_some_and(lower) && chars.all(|c| lower(c) || matches!(c, '_' | '.' | '-'))
}
