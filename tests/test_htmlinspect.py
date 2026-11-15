"""HTML inspection tests: meta refresh + canonical via a real parser."""

from app.htmlinspect import inspect_html


def test_meta_refresh_double_quotes():
    signals = inspect_html(
        '<meta http-equiv="refresh" content="0; url=http://example.com/target">'
    )
    assert signals["meta_refresh"] == (0, "http://example.com/target")


def test_meta_refresh_single_quotes_and_uppercase():
    signals = inspect_html(
        "<META HTTP-EQUIV='refresh' CONTENT='5; URL=/next'>"
    )
    assert signals["meta_refresh"] == (5, "/next")


def test_meta_refresh_unquoted_attributes():
    signals = inspect_html(
        '<meta http-equiv=refresh content="3;url=http://example.com/x">'
    )
    assert signals["meta_refresh"] == (3, "http://example.com/x")


def test_meta_refresh_without_url_ignored():
    signals = inspect_html('<meta http-equiv="refresh" content="10">')
    assert signals["meta_refresh"] is None


def test_canonical_href_after_rel():
    signals = inspect_html(
        '<link rel="canonical" href="http://example.com/real">'
    )
    assert signals["canonical_url"] == "http://example.com/real"
    assert signals["canonical_source"] == "rel=canonical"


def test_canonical_href_before_rel():
    signals = inspect_html(
        '<link href="http://example.com/real" rel="canonical">'
    )
    assert signals["canonical_url"] == "http://example.com/real"
    assert signals["canonical_source"] == "rel=canonical"


def test_og_url_fallback_only_without_canonical():
    signals = inspect_html(
        '<meta property="og:url" content="http://example.com/og">'
    )
    assert signals["canonical_url"] == "http://example.com/og"
    assert signals["canonical_source"] == "og:url"


def test_canonical_beats_og_url():
    signals = inspect_html(
        '<link rel="canonical" href="http://example.com/real">'
        '<meta property="og:url" content="http://example.com/og">'
    )
    assert signals["canonical_url"] == "http://example.com/real"
    assert signals["canonical_source"] == "rel=canonical"


def test_no_signals():
    signals = inspect_html("<html><head><title>plain</title></head></html>")
    assert signals["meta_refresh"] is None
    assert signals["canonical_url"] is None
    assert signals["canonical_source"] is None


def test_malformed_html_does_not_raise():
    signals = inspect_html("<meta http-equiv=refresh content=0;url=/x><link rel=canonical")
    assert signals["meta_refresh"] == (0, "/x")
