//! `#[req("FR-06", ...)]`: tags a test with the requirements it proves.
//!
//! The attribute goes on a test function, above its `#[test]` attribute (an attribute placed below
//! `#[test]` never sees it). At compile time it checks that every id has the format of a requirement id
//! (`FR-06`, `NFR-09`, `DEEP-01`, ...) or is the reserved `TOOLING`; anywhere else it is a compile error.
//! It makes the test print one `ostia-req: <ids>` line (sorted, comma-separated) when it runs. The nextest
//! `JUnit` report keeps that line (`store-success-output` in `.config/nextest.toml`), and the traceability
//! matrix (`tools/traceability/matrix.py`) reads each test's ids from it and checks them against the
//! requirements registry.
//!
//! ```ignore
//! use ostia_traceability::req;
//!
//! #[req("FR-06", "SEC-10")]
//! #[test]
//! fn too_deep_archive_is_unscannable() {}
//! ```

use proc_macro::{Delimiter, Group, Ident, Literal, Punct, Spacing, Span, TokenStream, TokenTree};

/// Requirement families of the specification.
const FAMILIES: [&str; 11] = [
    "FR", "NFR", "ENG", "USB", "DEEP", "ENR", "SEC", "CTR", "LOG", "UI", "UPD",
];

/// Reserved id for tests of helpers, fixtures and tooling.
const TOOLING: &str = "TOOLING";

/// Prefix of the line a tagged test prints; the traceability matrix looks for it.
const MARKER: &str = "ostia-req: ";

const PLACEMENT: &str = "#[req] goes on a test function, above its #[test] attribute";

/// Tags a test with the requirement ids it proves; a malformed id or a misplaced attribute is a
/// compile error.
#[proc_macro_attribute]
pub fn req(args: TokenStream, item: TokenStream) -> TokenStream {
    let ids = match requirement_ids(args) {
        Ok(ids) => ids,
        Err(message) => return compile_error(&message, item),
    };
    match with_marker(&item, &ids) {
        Some(tagged) => tagged,
        None => compile_error(PLACEMENT, item),
    }
}

/// The ids of the attribute arguments: string literals separated by commas, sorted, without duplicates.
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
    ids.sort();
    ids.dedup();
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

/// The test function with the marker line printed first, or `None` when the item is not a function
/// carrying a `#[test]`-like attribute (`#[test]`, `#[tokio::test]`, ...).
fn with_marker(item: &TokenStream, ids: &[String]) -> Option<TokenStream> {
    let mut tokens: Vec<TokenTree> = item.clone().into_iter().collect();
    let mut is_test = false;
    let mut is_function = false;
    let mut previous_is_hash = false;
    for token in &tokens {
        match token {
            TokenTree::Group(group)
                if previous_is_hash && group.delimiter() == Delimiter::Bracket =>
            {
                is_test |= attribute_is_test(group);
            }
            TokenTree::Ident(ident) if ident.to_string() == "fn" => is_function = true,
            _ => {}
        }
        previous_is_hash = matches!(token, TokenTree::Punct(punct) if punct.as_char() == '#');
    }
    let Some(TokenTree::Group(body)) = tokens.last() else {
        return None;
    };
    if !is_test || !is_function || body.delimiter() != Delimiter::Brace {
        return None;
    }
    let mut statements = marker_statement(&format!("{MARKER}{}", ids.join(",")));
    statements.extend(body.stream());
    let mut tagged = Group::new(Delimiter::Brace, statements);
    tagged.set_span(body.span());
    let last = tokens.len() - 1;
    tokens[last] = TokenTree::Group(tagged);
    Some(tokens.into_iter().collect())
}

/// Whether the attribute's path ends with `test` (`test`, `tokio::test`, ...).
fn attribute_is_test(attribute: &Group) -> bool {
    let mut last = None;
    for token in attribute.stream() {
        match token {
            TokenTree::Ident(ident) => last = Some(ident.to_string()),
            TokenTree::Punct(punct) if punct.as_char() == ':' => {}
            _ => break,
        }
    }
    last.as_deref() == Some("test")
}

/// `::std::println!("<line>");`
fn marker_statement(line: &str) -> TokenStream {
    let span = Span::call_site();
    let mut tokens = path_separator();
    tokens.push(TokenTree::Ident(Ident::new("std", span)));
    tokens.extend(path_separator());
    tokens.extend(macro_call("println", line));
    tokens.into_iter().collect()
}

/// `compile_error!("<message>");` followed by the item.
fn compile_error(message: &str, item: TokenStream) -> TokenStream {
    let mut tokens: TokenStream = macro_call("compile_error", message).into_iter().collect();
    tokens.extend(item);
    tokens
}

/// `<name>!("<argument>");`
fn macro_call(name: &str, argument: &str) -> Vec<TokenTree> {
    let span = Span::call_site();
    let arguments = TokenTree::Literal(Literal::string(argument)).into();
    vec![
        TokenTree::Ident(Ident::new(name, span)),
        TokenTree::Punct(Punct::new('!', Spacing::Alone)),
        TokenTree::Group(Group::new(Delimiter::Parenthesis, arguments)),
        TokenTree::Punct(Punct::new(';', Spacing::Alone)),
    ]
}

/// `::`
fn path_separator() -> Vec<TokenTree> {
    vec![
        TokenTree::Punct(Punct::new(':', Spacing::Joint)),
        TokenTree::Punct(Punct::new(':', Spacing::Alone)),
    ]
}
