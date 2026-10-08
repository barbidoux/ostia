//! `--flag value` pairs and capped file reads, shared by the subcommands (docs/contracts/cli.md).

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

/// The flags of one command line, each given once with a value.
#[derive(Debug, Default)]
pub struct Flags {
    values: BTreeMap<&'static str, PathBuf>,
}

impl Flags {
    /// Parse `--flag value` pairs; every flag must be one of `known`, once, with a value.
    ///
    /// # Errors
    /// The one-line usage error to print after `ostia: `.
    pub fn parse(args: &[OsString], known: &[&'static str]) -> Result<Self, String> {
        let mut flags = Self::default();
        let mut args = args.iter();
        while let Some(flag) = args.next() {
            let Some(name) = known.iter().copied().find(|k| flag.as_os_str() == *k) else {
                return Err(format!("unknown flag: {}", flag.to_string_lossy()));
            };
            let Some(value) = args.next() else {
                return Err(format!("missing value for {name}"));
            };
            if flags.values.insert(name, PathBuf::from(value)).is_some() {
                return Err(format!("flag given twice: {name}"));
            }
        }
        Ok(flags)
    }

    /// The value of a required flag.
    ///
    /// # Errors
    /// `missing flag: <name>`.
    pub fn required(&self, name: &'static str) -> Result<&Path, String> {
        self.values
            .get(name)
            .map(PathBuf::as_path)
            .ok_or_else(|| format!("missing flag: {name}"))
    }
}

/// At most `cap + 1` bytes of a file: enough for the caller to see that it is too large, never more.
///
/// # Errors
/// The I/O error of opening or reading the file.
pub fn read_capped(path: &Path, cap: usize) -> io::Result<Vec<u8>> {
    let limit = u64::try_from(cap).unwrap_or(u64::MAX).saturating_add(1);
    let mut bytes = Vec::new();
    File::open(path)?.take(limit).read_to_end(&mut bytes)?;
    Ok(bytes)
}
