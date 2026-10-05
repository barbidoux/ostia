//! Fixture crate for the traceability matrix tests (never compiled).

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

    #[test]
    #[req("TOOLING")]
    fn helper_works() {}

    /// Not a test: a req attribute only counts on a test function's own attributes.
    fn not_a_test() {}
}
