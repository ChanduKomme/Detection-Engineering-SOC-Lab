"""Guards for the CyberPulse console theme. Author: Chandu Komme

OpenSearch Dashboards refuses to start on an unknown configuration key, so the
mounted file may only use settings known to exist in Dashboards 2.19.
"""
from pathlib import Path
import json
import xml.dom.minidom

import yaml

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config/dashboards/opensearch_dashboards.yml"
BRANDING = ROOT / "config/dashboards/branding"
KNOWN = {
    "server.host", "opensearch.hosts", "opensearch.ssl.verificationMode", "opensearch.username",
    "opensearch.password", "opensearch.requestHeadersWhitelist",
    "opensearch_security.readonly_mode.roles", "opensearch_security.cookie.secure",
    "opensearch_security.multitenancy.enabled", "opensearchDashboards.branding",
    "opensearch_security.ui.basicauth.login.title", "opensearch_security.ui.basicauth.login.subtitle",
    "opensearch_security.ui.basicauth.login.showbrandimage",
    "opensearch_security.ui.basicauth.login.brandimage", "uiSettings",
}
BRANDING_KEYS = {"applicationTitle", "useExpandedHeader", "faviconUrl", "logo", "mark", "loadingLogo"}


def config():
    return yaml.safe_load(CONFIG.read_text(encoding="utf-8"))


def asset_urls(value):
    if isinstance(value, dict):
        for item in value.values():
            yield from asset_urls(item)
    elif isinstance(value, str) and "/ui/cyberpulse/" in value:
        yield value


def test_only_known_settings():
    data = config()
    assert set(data) <= KNOWN, set(data) - KNOWN
    assert set(data["opensearchDashboards.branding"]) <= BRANDING_KEYS
    assert set(data["uiSettings"]) == {"overrides"}


def test_every_branding_asset_exists_and_is_valid_svg():
    urls = list(asset_urls(config()))
    assert len(urls) == 8
    for url in urls:
        assert url.startswith("http://localhost:5601/ui/cyberpulse/") and url.endswith(".svg")
        path = BRANDING / url.rsplit("/", 1)[1]
        assert path.is_file(), path
        xml.dom.minidom.parse(str(path))


def test_theme_overrides():
    overrides = config()["uiSettings"]["overrides"]
    assert overrides["theme:darkMode"] is True
    assert overrides["defaultRoute"].endswith("/cyberpulse-soc-dashboard")
    colors = json.loads(overrides["visualization:colorMapping"])
    assert colors["windows.security"] == "#00E5FF" and colors["suricata.eve"] == "#FF4D6D"


def test_compose_mounts_the_theme():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    assert compose["name"] == "cyberpulse-soc-lab"
    volumes = compose["services"]["dashboards"]["volumes"]
    assert any(v.startswith("./config/dashboards/opensearch_dashboards.yml:") for v in volumes)
    assert any(v.startswith("./config/dashboards/branding:") and v.endswith("/assets/cyberpulse:ro") for v in volumes)
