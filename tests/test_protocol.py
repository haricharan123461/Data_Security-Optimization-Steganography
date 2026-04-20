from comet_optimizer import optimize_with_comet


def test_optimizer_roundtrip_fidelity():
    message = "Hello Client B - secure payload"
    result = optimize_with_comet(message=message, iterations=2, comet_count=8)
    assert result.best_result.decrypted_bytes.decode("utf-8") == message
    assert result.best_result.score > 0.5
    assert result.exhaustive_method_count == 24
    assert "Exhaustive DNA Permutation Search" in result.optimization_methods
    assert "COMET (Characteristic Objects Method)" in result.optimization_methods
    assert "Hill-Climbing Local Search" in result.optimization_methods
    assert len(result.compliance_trace) >= 4


def test_candidate_table_available():
    message = "Test message"
    result = optimize_with_comet(message=message, iterations=1, comet_count=8)
    assert len(result.all_results) >= 24
    method_names = {item.candidate_name for item in result.all_results if item.candidate_name.startswith("DNA-Perm-")}
    assert len(method_names) == 24


def test_image_payload_roundtrip_uses_dna_pipeline():
    png_like_bytes = bytes([137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82])
    result = optimize_with_comet(payload_bytes=png_like_bytes, payload_type="image", iterations=2, comet_count=8)
    assert result.best_result.decrypted_bytes == png_like_bytes
    assert result.exhaustive_method_count == 24
