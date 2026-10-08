//! One engine's result for one object: the full `AnalyzeResponse` of `ostia.engine.v1` (spec §14).

use ostia_contracts::v1::AnalyzeResponse;

/// An engine's answer, as received (or as synthesised by the worker host on crash or timeout).
#[derive(Debug, Clone, PartialEq)]
pub struct EngineResult(AnalyzeResponse);

impl EngineResult {
    /// Wrap a response.
    #[must_use]
    pub fn new(response: AnalyzeResponse) -> Self {
        Self(response)
    }

    /// The response.
    #[must_use]
    pub fn response(&self) -> &AnalyzeResponse {
        &self.0
    }

    /// The engine id (CTR-03).
    #[must_use]
    pub fn engine_id(&self) -> &str {
        todo!("WP-1.1: engine result")
    }
}
