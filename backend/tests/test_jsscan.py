from app.farm import jsscan


def test_find_secrets_catches_prefixed_keys() -> None:
    text = (
        'const c={awsKey:"AKIAIOSFODNN7EXAMPLE",'
        'g:"AIzaSyA1234567890abcdefghijklmnopqrstuv",'
        'gh:"ghp_0123456789abcdefghijklmnopqrstuvwxyz"};'
        'var pk="-----BEGIN RSA PRIVATE KEY-----MIIB";'
    )
    kinds = {s.kind: s for s in jsscan.find_secrets(text)}
    assert kinds["aws_access_key"].severity == "high"
    assert "google_api_key" in kinds
    assert "github_pat" in kinds
    assert "private_key" in kinds


def test_find_secrets_specific_wins_over_generic() -> None:
    # apiKey="AKIA…" ловится и aws_access_key, и generic — остаётся специфичный.
    secrets = jsscan.find_secrets('apiKey: "AKIAIOSFODNN7EXAMPLE"')
    assert [s.kind for s in secrets] == ["aws_access_key"]


def test_find_secrets_generic_needs_a_hint_and_length() -> None:
    # Есть подсказка + длинный литерал → находка.
    assert jsscan.find_secrets('password: "s3cr3tValue1234567"')
    # Короткий литерал под ключом-подсказкой — не секрет.
    assert not jsscan.find_secrets('password: "short"')
    # Длинная строка без подсказки — тоже нет.
    assert not jsscan.find_secrets('label = "just-a-very-long-plain-label-string"')


def test_redact_hides_the_middle() -> None:
    assert jsscan.redact("AKIAIOSFODNN7EXAMPLE") == "AKIA…MPLE"
    assert "***" in jsscan.redact("secret12")
    assert jsscan.redact("") == ""


def test_find_paths_keeps_routes_drops_static() -> None:
    text = (
        'fetch("/api/v1/users");axios.get("/admin/settings");'
        'img.src="/assets/logo.png";load("vendor/app.chunk");'
        'u="https://api.acme.com/v2/orders";x="node_modules/lib";'
    )
    paths = jsscan.find_paths(text)
    assert "/api/v1/users" in paths
    assert "/admin/settings" in paths
    assert "https://api.acme.com/v2/orders" in paths
    assert "/assets/logo.png" not in paths  # статика отсеяна
    assert not any("node_modules" in p for p in paths)


def test_extract_js_urls_resolves_relative_and_skips_analytics() -> None:
    html = (
        '<script src="/static/app.bundle.js"></script>'
        '<script src="https://cdn.acme.com/vendor.js"></script>'
        '<script src="https://www.google-analytics.com/ga.js"></script>'
        '<link href="/style.css">'
    )
    urls = jsscan.extract_js_urls(html, "https://acme.com/")
    assert "https://acme.com/static/app.bundle.js" in urls  # относительный → абсолютный
    assert "https://cdn.acme.com/vendor.js" in urls
    assert not any("google-analytics" in u for u in urls)  # аналитика в денилисте
    assert not any(u.endswith(".css") for u in urls)


def test_extract_js_urls_dedups() -> None:
    html = '<script src="/a.js"></script><script src="/a.js"></script>'
    assert jsscan.extract_js_urls(html, "https://acme.com/") == ["https://acme.com/a.js"]
