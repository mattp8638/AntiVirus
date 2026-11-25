"""VULN-22: the server connects only to public addresses that customers supply, pinned against DNS rebinding."""

import pytest

from fenrir_cloud import exposure, netguard
from fenrir_cloud.models import ExternalAsset


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.1", "169.254.169.254", "100.64.0.1",
                                     "::1", "fe80::1", "fd00:ec2::254", "::ffff:127.0.0.1", "0.0.0.0", "224.0.0.1"])
def test_non_public_addresses_are_refused(address):
    assert not netguard.is_public(address)
    with pytest.raises(netguard.Blocked):
        netguard.resolve_public(address)


def test_public_addresses_pass_and_private_needs_opt_in(monkeypatch):
    assert netguard.is_public("8.8.8.8") and netguard.is_public("2001:4860:4860::8888")
    monkeypatch.setenv("FENRIR_ALLOW_PRIVATE_TARGETS", "true")
    assert netguard.is_public("10.0.0.5"), "a self-hosted single-organisation install may allow private targets"
    assert not netguard.is_public("169.254.169.254") and not netguard.is_public("127.0.0.1"), "never metadata or loopback"


def test_a_name_resolving_to_a_private_address_is_refused(monkeypatch):
    monkeypatch.setattr(netguard, "resolve", lambda host: ["93.184.216.34", "10.1.2.3"])
    with pytest.raises(netguard.Blocked, match="10.1.2.3"):
        netguard.resolve_public("rebind.example")


def test_external_scan_refuses_internal_and_pins_the_checked_address(monkeypatch):
    monkeypatch.setattr(netguard, "resolve", lambda host: ["169.254.169.254"])
    r = exposure.scan_external(ExternalAsset(tenant_id="t", target="metadata.example"), ports=[80])
    assert r["error"].startswith("Not scanned") and r["openPorts"] == []
    seen = []
    monkeypatch.setattr(netguard, "resolve", lambda host: ["93.184.216.34"])
    monkeypatch.setattr(exposure, "_probe", lambda host, port, timeout: seen.append(host) or None)
    exposure.scan_external(ExternalAsset(tenant_id="t", target="www.example"), ports=[80, 443])
    assert set(seen) == {"93.184.216.34"}, "probes go to the checked address, not a fresh lookup"


def test_assets_monitors_and_webhooks_refuse_internal_targets(client, admin, tenant):
    tid = tenant["id"]
    r = client.post("/api/console/exposure/assets", headers=admin, json={"tenantId": tid, "target": "169.254.169.254", "ownershipConfirmed": True})
    assert r.status_code == 400 and "public" in r.text
    r = client.post("/api/console/network/monitors", headers=admin, json={"tenantId": tid, "name": "x", "address": "10.0.0.1", "port": 80})
    assert r.status_code == 400 and "probe device" in r.text
    r = client.post("/api/console/webhooks", headers=admin, json={"tenantId": tid, "url": "https://127.0.0.1/hook"})
    assert r.status_code == 400 and "refused" in r.text
