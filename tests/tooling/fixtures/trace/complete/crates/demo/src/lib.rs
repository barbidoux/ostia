//! Fixture crate for the traceability matrix tests (never compiled). The matrix reads the ids of the
//! tests that ran from the nextest report; it only checks the ids written in the sources against the
//! registry.

/// Reads nothing.
pub fn read() {}

#[cfg(test)]
mod tests {
    use ostia_traceability::req;

    #[req("FR-01")]
    #[test]
    fn medium_is_read_only() {
        super::read();
    }

    #[req("TOOLING")]
    #[test]
    fn helper_works() {}
}
