//! An engine result keeps the whole `AnalyzeResponse` and its engine identity (spec §14, CTR-03).

use ostia_contracts::v1::AnalyzeResponse;
use ostia_core_domain::engine::EngineResult;
use ostia_traceability::req;

#[req("FR-09", "CTR-03")]
#[test]
fn engine_result_keeps_the_response_and_its_engine_id() {
    let response = AnalyzeResponse {
        engine_id: "fake-av".into(),
        engine_version: "1.0.0".into(),
        content_version: "rules-1".into(),
        score: Some(0.25),
        duration_ms: 5,
        ..AnalyzeResponse::default()
    };
    let result = EngineResult::new(response.clone());
    assert_eq!(result.engine_id(), "fake-av");
    assert_eq!(result.response(), &response);
}
