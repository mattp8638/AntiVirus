"""Tests for enhanced DNS filtering and external blocklist (HaGeZi, Spydi, OISD) ingestion."""

import httpx

from fenrir_cloud import blocklists
from fenrir_cloud.dnsfilter import decide, looks_like_dga


def test_parse_raw_blocklist_formats():
    raw = """
    # Comment line
    ! AdBlock comment
    ; Another comment
    0.0.0.0 bad-hosts.com
    127.0.0.1 tracker.adserver.net
    ||ad.doubleclick.net^
    plain-malware-domain.org
    *.wild.example.net
    @@||exception.example.com^
    localhost
    not a domain
    """
    domains = blocklists.parse(raw)

    assert "bad-hosts.com" in domains
    assert "tracker.adserver.net" in domains
    assert "ad.doubleclick.net" in domains
    assert "plain-malware-domain.org" in domains
    assert "wild.example.net" in domains
    assert "exception.example.com" not in domains
    assert "localhost" not in domains
    assert not any(d.startswith("#") or " " in d for d in domains)


def test_decide_zero_breakage_allowlist_override():
    dns_settings = {
        "allowDomains": ["legitimate-corporate-site.com"],
        "blockDomains": ["badsite.com"],
        "blockedCategories": ["malware", "ads-trackers"],
    }
    intel = {
        "legitimate-corporate-site.com": ("malicious", "malware"),
        "badsite.com": ("malicious", "malware"),
    }

    # Policy allowList MUST override threat intel block (zero-breakage guarantee)
    dec = decide("legitimate-corporate-site.com", dns_settings, intel)
    assert dec.action == "allow"
    assert dec.reason == "allow-list"

    # Policy blockList blocks
    dec_block = decide("badsite.com", dns_settings, intel)
    assert dec_block.action == "block"


def test_looks_like_dga():
    assert looks_like_dga("x7z9q3m1k9p2v8.com") is True
    assert looks_like_dga("google.com") is False
    assert looks_like_dga("microsoft.com") is False


def _feed(body: str, status: int = 200, etag: str = "v1"):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.headers.get("if-none-match") == etag:
            return httpx.Response(304)
        return httpx.Response(status, text=body, headers={"ETag": etag})

    return httpx.Client(transport=httpx.MockTransport(handler)), calls


def test_blocklist_sync_blocks_through_resolver_and_keeps_safety_rules(client, admin, tenant):
    from fenrir_cloud.db import session_factory

    lists = client.get("/api/console/dns/blocklists", headers=admin).json()
    assert {row["id"] for row in lists} >= {"hagezi-tif-mini", "hagezi-pro"}
    assert next(row for row in lists if row["id"] == "hagezi-tif-mini")["enabled"] is True

    feed = "\n".join(f"bad{i}.example" for i in range(100)) + "\nc2.evil.example\n"
    http, calls = _feed(feed)
    with session_factory()() as db:
        row = db.get(blocklists.DnsBlocklist, "hagezi-tif-mini")
        assert blocklists.fetch(db, row, http)["domains"] == 101
        db.commit()
        # Unchanged lists are not downloaded again.
        assert blocklists.fetch(db, row, http).get("unchanged") is True
        assert calls[-1].headers["if-none-match"] == "v1"
        # A truncated download is held back rather than unblocking most of the list.
        short, _ = _feed("bad1.example\n", etag="v2")
        result = blocklists.fetch(db, row, short)
        assert result["updated"] is False and "shrank" in result["error"]
        assert row.domain_count == 101
        # An empty or failed download keeps the previous copy.
        broken, _ = _feed("<html>error</html>", etag="v3")
        assert blocklists.fetch(db, row, broken)["updated"] is False
        failed, _ = _feed("", status=503, etag="v4")
        assert "Download failed" in blocklists.fetch(db, row, failed)["error"]
        assert row.domain_count == 101
        db.commit()

    blocked = client.get("/api/console/dns/check", params={"domain": "www.c2.evil.example", "tenant_id": tenant["id"]}, headers=admin).json()
    assert blocked["action"] == "block" and blocked["reason"] == "blocklist hagezi-tif-mini"

    # An analyst's allow indicator overrides the external list.
    response = client.post("/api/console/intel/indicators", json={"values": ["c2.evil.example"], "verdict": "allow", "tenantId": tenant["id"]},
                           headers=admin)
    assert response.status_code == 200 and response.json()["added"] == 1, response.text
    from fenrir_cloud.dnsfilter import INTEL

    INTEL.invalidate()
    allowed = client.get("/api/console/dns/check", params={"domain": "c2.evil.example", "tenant_id": tenant["id"]}, headers=admin).json()
    assert allowed["action"] == "allow", allowed

    # Disabling the list stops it blocking.
    assert client.patch("/api/console/dns/blocklists/hagezi-tif-mini", json={"enabled": False}, headers=admin).status_code == 200
    after = client.get("/api/console/dns/check", params={"domain": "bad5.example", "tenant_id": tenant["id"]}, headers=admin).json()
    assert after["action"] == "allow", after


def test_non_malware_lists_only_apply_where_the_category_is_blocked():
    ads = blocklists.ActiveList("hagezi-pro", "ads-trackers", frozenset({"tracker.example"}))
    assert decide("pixel.tracker.example", {"blockedCategories": ["malware"]}, {}, [ads]).action == "allow"
    assert decide("pixel.tracker.example", {"blockedCategories": ["ads-trackers"]}, {}, [ads]).action == "block"
    assert decide("pixel.tracker.example", {"allowDomains": ["tracker.example"], "blockedCategories": ["ads-trackers"]}, {},
                  [ads]).action == "allow"


def test_blocklist_management_is_platform_only(client, admin, tenant):
    from conftest import login

    client.post("/api/console/users", json={"email": "ta@acme.test", "name": "T", "role": "tenant_admin", "tenantId": tenant["id"],
                                            "password": "a-long-enough-password-1"}, headers=admin)
    tenant_admin = login(client, "ta@acme.test", "a-long-enough-password-1")
    assert client.patch("/api/console/dns/blocklists/hagezi-tif-mini", json={"enabled": False}, headers=tenant_admin).status_code == 403
    assert client.post("/api/console/dns/blocklists", json={"id": "x", "url": "http://insecure"}, headers=admin).status_code == 422
    created = client.post("/api/console/dns/blocklists", json={"id": "custom-list", "url": "https://lists.example/d.txt", "category": "malware"},
                          headers=admin)
    assert created.status_code == 200
    assert client.delete("/api/console/dns/blocklists/hagezi-pro", headers=admin).status_code == 409
    assert client.delete("/api/console/dns/blocklists/custom-list", headers=admin).status_code == 200
