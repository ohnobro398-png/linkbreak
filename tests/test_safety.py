"""Scam-safety analysis tests (pure URL facts, no external lookups)."""

from app.safety import analyze_safety


def test_brand_mismatch_flagged():
    result = analyze_safety(
        "http://" + "amzn.to/abc", "http://evil.example.com/x"
    )
    assert result["brand_mismatch"] is True
    assert result["final_domain"] == "evil.example.com"
    assert any("suspicion" in note for note in result["safety_notes"])


def test_brand_match_not_flagged():
    result = analyze_safety(
        "http://" + "amzn.to/abc", "http://www.amazon.com/product"
    )
    assert result["brand_mismatch"] is False


def test_domain_changed_generic_shortener():
    result = analyze_safety("http://" + "bit.ly/abc", "http://example.com/x")
    assert result["domain_changed"] is True
    assert result["brand_mismatch"] is False
    assert any("differs" in note for note in result["safety_notes"])


def test_same_domain_not_changed():
    result = analyze_safety("http://example.com/a", "http://example.com/b")
    assert result["domain_changed"] is False
    assert result["brand_mismatch"] is False


def test_bare_ip_final_destination_noted():
    result = analyze_safety("http://example.com/a", "http://93.184.216.34/x")
    assert any("bare IP" in note for note in result["safety_notes"])


def test_http_final_destination_noted():
    result = analyze_safety("http://example.com/a", "http://example.com/x")
    assert any("not encrypted" in note for note in result["safety_notes"])


def test_https_final_destination_not_flagged_for_http():
    result = analyze_safety("http://example.com/a", "https://example.com/x")
    assert not any("not encrypted" in note for note in result["safety_notes"])


def test_punycode_final_domain_noted():
    result = analyze_safety("http://example.com/a", "http://xn--exmple-cua.com/x")
    assert any("punycode" in note for note in result["safety_notes"])


def test_userinfo_trick_noted():
    result = analyze_safety(
        "http://example.com/a", "http://example.com@evil.com/x"
    )
    assert result["final_domain"] == "evil.com"
    assert any("@" in note for note in result["safety_notes"])


def test_no_final_url_is_quiet():
    result = analyze_safety("http://" + "bit.ly/abc", None)
    assert result["final_domain"] is None
    assert result["domain_changed"] is False
    assert result["brand_mismatch"] is False
    assert result["safety_notes"] == []
