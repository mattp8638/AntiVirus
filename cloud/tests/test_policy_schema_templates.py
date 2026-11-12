"""The operating-system templates: valid, and the server ones never take risky automatic actions."""
from fenrir_cloud import policy_schema as ps

OS_TEMPLATES = ["windows-workstation", "windows-server", "linux-workstation", "linux-server", "macos-workstation", "macos-server"]


def test_os_templates_exist_and_validate():
    for name in OS_TEMPLATES:
        assert name in ps.TEMPLATES and ps.TEMPLATES[name]["_label"]
        ps.validate_partial(ps.template_settings(name))


def test_server_templates_are_conservative():
    for name in (n for n in OS_TEMPLATES if n.endswith("-server")):
        t = ps.template_settings(name)
        assert t.get("dns", {}).get("localProxy", False) is False  # no loopback DNS on servers
        assert t["response"]["autoIsolateOnCritical"] is False
        assert t["privilege"].get("removeLocalAdmins", False) is False
        assert t["privilege"]["enabled"] is False or name == "windows-server"
        assert t["patch"]["rebootBehaviour"] == "never"
        if name.startswith("windows"):
            assert t["experience"]["notifications"] == "none"


def test_macs_never_use_the_loopback_dns_proxy():
    for name in ("macos-workstation", "macos-server"):
        assert ps.template_settings(name).get("dns", {}).get("localProxy", False) is False
    assert "macos" not in ps.AGENT_SUPPORT["dns.localProxy"]


def test_workstation_dns_proxy_fails_open():
    for name in ("windows-workstation", "linux-workstation"):
        dns = ps.template_settings(name)["dns"]
        assert dns["localProxy"] is True and dns["localProxyFailMode"] == "open"


def test_mac_and_linux_templates_only_use_settings_their_agent_enforces():
    for name, platform in (("linux-workstation", "linux"), ("linux-server", "linux"),
                           ("macos-workstation", "macos"), ("macos-server", "macos")):
        for section, values in ps.template_settings(name).items():
            for key in values:
                path = f"{section}.{key}"
                support = ps.AGENT_SUPPORT.get(path)
                assert support is None or platform in support, f"{name}: {path} is not enforced on {platform}"


def test_android_template_is_moderate():
    t = ps.template_settings("android")
    ps.validate_partial(t)
    assert set(t) == {"mobile", "android"}  # phones only: nothing for the desktop agents
    assert t["android"]["blockUnknownSources"] is True and t["mobile"]["suspendMalicious"] is True
    assert t["android"]["wipeAfterFailedAttempts"] == 0 and t["android"]["disableCamera"] is False
