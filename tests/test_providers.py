"""Provider registry tests."""

from app.providers import detect_provider, register_provider


def test_known_shorteners_named():
    assert detect_provider("bit.ly") == ("bit.ly", False, None)
    assert detect_provider("tinyurl.com") == ("TinyURL", False, None)
    assert detect_provider("t.co")[0] == "X (t.co)"
    assert detect_provider("is.gd")[0] == "is.gd"
    assert detect_provider("cutt.ly")[0] == "Cutt.ly"
    assert detect_provider("rebrand.ly")[0] == "Rebrandly"
    assert detect_provider("shorturl.at")[0] == "shorturl.at"
    assert detect_provider("buff.ly")[0].startswith("Buffer")
    assert detect_provider("ow.ly")[0].startswith("Hootsuite")
    assert detect_provider("rb.gy")[0] == "rb.gy"
    assert detect_provider("s.id")[0] == "s.id"
    assert detect_provider("v.gd")[0] == "v.gd"


def test_expanded_registry_named():
    assert detect_provider("j.mp")[0] == "j.mp (Bitly)"
    assert detect_provider("youtu.be")[0].startswith("YouTube")
    assert detect_provider("amzn.to")[0].startswith("Amazon")
    assert detect_provider("t.ly")[0] == "T.ly"
    assert detect_provider("kutt.it")[0] == "Kutt"
    assert detect_provider("gg.gg")[0] == "gg.gg"
    assert detect_provider("fb.me")[0].startswith("Facebook")
    assert detect_provider("spoo.me")[0] == "Spoo.me"
    assert detect_provider("trib.al")[0] == "Trib.al"


def test_subdomain_matches_provider():
    assert detect_provider("www.bit.ly")[0] == "bit.ly"
    assert detect_provider("www.linkvertise.com")[1] is True


def test_unknown_host_is_generic():
    name, unsupported, reason = detect_provider("example.com")
    assert name == "example.com"
    assert unsupported is False
    assert reason is None


def test_js_ad_gated_are_unsupported():
    for host in ("linkvertise.com", "adf.ly", "ouo.io", "shrinkme.io",
                 "shorte.st", "exe.io", "adfoc.us", "bc.vc", "clk.sh",
                 "sh.st", "linkbucks.com", "ity.im"):
        _name, unsupported, reason = detect_provider(host)
        assert unsupported is True, host
        assert reason, host


def test_register_provider_plugin_hook():
    register_provider("short.example", "Example Shortener")
    assert detect_provider("short.example") == ("Example Shortener", False, None)
    assert detect_provider("sub.short.example")[0] == "Example Shortener"
