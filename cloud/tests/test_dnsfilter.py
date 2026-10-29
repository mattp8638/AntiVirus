"""Tests for enhanced DNS filtering and external blocklist (HaGeZi, Spydi, OISD) ingestion."""

from fenrir_cloud.dnsfilter import Decision, decide, looks_like_dga
from fenrir_cloud.intel import parse_raw_blocklist, sync_external_blocklist_feed


def test_parse_raw_blocklist_formats():
    raw = """
    # Comment line
    ! AdBlock comment
    ; Another comment
    0.0.0.0 bad-hosts.com
    127.0.0.1 tracker.adserver.net
    ||ad.doubleclick.net^
    plain-malware-domain.org
    """
    domains = parse_raw_blocklist(raw)

    assert "bad-hosts.com" in domains
    assert "tracker.adserver.net" in domains
    assert "ad.doubleclick.net" in domains
    assert "plain-malware-domain.org" in domains
    assert not any(d.startswith("#") for d in domains)


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


def test_sync_external_blocklist_feed(client, admin, tenant):
    # Ingest sample blocklist feed content
    raw_feed = "0.0.0.0 C2-server.evil.com\n||phishing-target.net^\n"
    from fenrir_cloud.db import session_factory

    with session_factory()() as db:
        count = sync_external_blocklist_feed(db, "hagezi-tif", raw_feed, category="malware")
        db.commit()
        assert count == 2
