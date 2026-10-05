//! `#[req("FR-06", ...)]`: tags a test with the requirements it proves.
//!
//! The attribute leaves the item it decorates unchanged. At compile time it only checks that every id
//! has the format of a requirement id (`FR-06`, `NFR-09`, `DEEP-01`, ...) or is the reserved `TOOLING`.
//! The traceability matrix (`tools/traceability/matrix.py`) reads the ids from the source and checks
//! them against the requirements registry.
//!
//! ```ignore
//! use ostia_traceability::req;
//!
//! #[req("FR-06", "SEC-10")]
//! #[test]
//! fn too_deep_archive_is_unscannable() {}
//! ```

use proc_macro::{TokenStream, TokenTree};

/// Requirement families of the specification.
const FAMILIES: [&str; 11] = [
    "FR", "NFR", "ENG", "USB", "DEEP", "ENR", "SEC", "CTR", "LOG", "UI", "UPD",
];

/// Reserved id for tests of helpers, fixtures and tooling.
const TOOLING: &str = "TOOLING";

/// Tags a test with the requirement ids it proves; a malformed id is a compile error.
#[proc_macro_attribute]
pub fn req(args: TokenStream, item: TokenStream) -> TokenStream {
    match requirement_ids(args) {
        Ok(_) => item,
        Err(message) => compile_error(&message, item),
    }
}

/// The ids of the attribute arguments: string literals separated by commas.
fn requirement_ids(args: TokenStream) -> Result<Vec<String>, String> {
    let mut ids = Vec::new();
    let mut expect_id = true;
    for token in args {
        match token {
            TokenTree::Literal(literal) if expect_id => {
                let text = literal.to_string();
                let id = text
                    .strip_prefix('"')
                    .and_then(|rest| rest.strip_suffix('"'))
                    .ok_or_else(|| "#[req] takes string literals".to_owned())?;
                if !is_requirement_id(id) {
                    return Err(format!("invalid requirement id \"{id}\""));
                }
                ids.push(id.to_owned());
                expect_id = false;
            }
            TokenTree::Punct(punct) if !expect_id && punct.as_char() == ',' => expect_id = true,
            _ => return Err("#[req] takes string literals".to_owned()),
        }
    }
    if ids.is_empty() {
        return Err("#[req] needs at least one requirement id".to_owned());
    }
    Ok(ids)
}

/// `FAMILY-NN` with a known family and exactly two digits, or `TOOLING`.
fn is_requirement_id(id: &str) -> bool {
    if id == TOOLING {
        return true;
    }
    match id.split_once('-') {
        Some((family, number)) => {
            FAMILIES.contains(&family)
                && number.len() == 2
                && number.bytes().all(|byte| byte.is_ascii_digit())
        }
        None => false,
    }
}

/// The item preceded by a `compile_error!` carrying the message.
fn compile_error(message: &str, item: TokenStream) -> TokenStream {
    let mut tokens: TokenStream = format!("compile_error!({message:?});")
        .parse()
        .unwrap_or_default();
    tokens.extend(item);
    tokens
}
