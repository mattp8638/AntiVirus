"""Free threat-intel feeds pulled by the server (threat_feeds.py), with the safety guards around them."""

import json

import httpx

from fenrir_cloud import db as database, dnsfilter, intel, threat_feeds
from fenrir_cloud.models import Indicator, IntelFeed

SHA = "a" * 64
SHA2 = "b" * 64

BAZAAR = f'''################################################################
# MalwareBazaar recent malware samples (CSV)                   #
################################################################
# "first_seen_utc","sha256_hash","md5_hash","sha1_hash","reporter","file_name","file_type_guess","mime_type","signature","clamav","vtpercent","imphash","ssdeep","tlsh"
"2026-11-11 08:00:01", "{SHA}", "{'c' * 32}", "{'d' * 40}", "abuse_ch", "invoice.exe", "exe", "application/x-dosexec", "AgentTesla", "n/a", "61.5", "x", "y", "z"
"2026-11-11 08:01:01", "{SHA2}", "{'e' * 32}", "{'f' * 40}", "abuse_ch", "a.dll", "dll", "application/x-dosexec", "n/a", "n/a", "n/a", "x", "y", "z"
'''
URLHAUS = '''# URLhaus Database Dump (CSV - recent URLs only)
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"3000001","2026-11-11 08:00:00","http://evil-dropper.example/bin.exe","online","2026-11-11 08:00:00","malware_download","exe","https://urlhaus.abuse.ch/url/3000001/","x"
"3000002","2026-11-11 08:00:00","https://github.com/someone/repo/raw/main/payload.exe","online","2026-11-11 08:00:00","malware_download","exe","https://urlhaus.abuse.ch/url/3000002/","x"
"3000003","2026-11-11 08:00:00","http://old.example/gone.exe","offline","","malware_download","exe","https://urlhaus.abuse.ch/url/3000003/","x"
'''
HOSTFILE = "# URLhaus hostfile\n127.0.0.1\tmalware-host.example\n127.0.0.1\tgithub.com\n127.0.0.1\tsub.drive.google.com\n"
THREATFOX = json.dumps({"1": [{"ioc_value": "198.51.100.7:443", "ioc_type": "ip:port", "threat_type": "botnet_cc", "malware_printable": "Cobalt Strike", "confidence_level": 100}],
                        "2": [{"ioc_value": "c2.badness.example", "ioc_type": "domain", "threat_type": "botnet_cc", "malware_printable": "AsyncRAT", "confidence_level": 75}],
                        "3": [{"ioc_value": "c" * 64, "ioc_type": "sha256_hash", "threat_type": "payload", "malware_printable": "Lumma", "confidence_level": 50}]})
FEODO = json.dumps([{"ip_address": "203.0.113.9", "port": 443, "status": "online", "malware": "QakBot"},
                    {"ip_address": "203.0.113.10", "port": 8080, "status": "offline", "malware": "Emotet"}])
IPSUM = "# IPsum\n192.0.2.44\t5\n192.0.2.45\t3\n"

BODIES = {"bazaar.abuse.ch": BAZAAR, "urlhaus.abuse.ch/downloads/csv_recent": URLHAUS, "urlhaus.abuse.ch/downloads/hostfile": HOSTFILE,
          "threatfox.abuse.ch": THREATFOX, "feodotracker.abuse.ch": FEODO, "stamparm/ipsum": IPSUM}


def transport(status=200, seen=None, override=None):
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if seen is not None:
            seen.append((url, dict(request.headers)))
        for key, body in {**BODIES, **(override or {})}.items():
            if key in url:
                return httpx.Response(status, text=body if status == 200 else "denied", headers={"etag": '"v1"'})
        return httpx.Response(404)
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_every_feed_parses_and_lands_as_indicators(client):
    with database.session_factory()() as db:
        results = threat_feeds.sync(db, only_due=False, client=transport())
        assert all(r["ok"] for r in results), results
        by_source = {}
        for row in db.query(Indicator).filter(Indicator.source.like("feed:%")).all():
            by_source.setdefault(row.source, set()).add((row.type, row.value, row.verdict))
    assert by_source["feed:malwarebazaar-recent"] == {("sha256", SHA, "malicious"), ("sha256", SHA2, "malicious")}
    urls = {v for _, v, _ in by_source["feed:urlhaus-recent"]}
    assert "http://evil-dropper.example/bin.exe" in urls and "http://old.example/gone.exe" not in urls  # online only
    assert {v for _, v, _ in by_source["feed:urlhaus-hosts"]} == {"malware-host.example"}  # shared platforms dropped
    assert ("ip", "198.51.100.7", "malicious") in by_source["feed:threatfox-recent"]
    assert ("domain", "c2.badness.example", "malicious") in by_source["feed:threatfox-recent"]
    assert by_source["feed:feodo-c2"] == {("ip", "203.0.113.9", "malicious")}
    assert by_source["feed:ipsum-3"] == {("ip", "192.0.2.44", "suspicious"), ("ip", "192.0.2.45", "suspicious")}


def test_lookup_finds_feed_indicators(client, admin):
    with database.session_factory()() as db:
        threat_feeds.sync(db, only_due=False, client=transport())
    hit = client.get("/api/console/intel/lookup", params={"value": SHA}, headers=admin).json()
    assert hit["verdict"] == "malicious" and hit["source"] == "feed:malwarebazaar-recent"
    feeds = client.get("/api/console/intel/feeds", headers=admin).json()
    assert {f["id"] for f in feeds["feeds"]} >= set(threat_feeds.BUILTIN) and all(f["indicators"] > 0 for f in feeds["feeds"])


def test_feed_links_never_block_whole_sites(client):
    with database.session_factory()() as db:
        threat_feeds.sync(db, only_due=False, client=transport())
        intel.upsert(db, "url", "https://github.com/manual/entry.exe", source="manual")
        db.commit()
        dnsfilter.INTEL.invalidate()
        domains = dnsfilter.INTEL.domains(db, None)
        bundle = intel.agent_bundle(db, None)
    assert "malware-host.example" in domains and "c2.badness.example" in domains
    assert "evil-dropper.example" not in domains  # a feed URL blocks the link (agents), not DNS for the site
    assert "github.com" not in domains            # shared platform, even from a manual URL
    hosts = {u["url"]: u["host"] for u in bundle["urls"]}
    assert hosts["http://evil-dropper.example/bin.exe"] == ""
    assert hosts["https://github.com/manual/entry.exe"] == ""
    assert hosts["http://malware-host.example/"] == "malware-host.example"


def test_failures_keep_the_previous_copy_and_say_why(client):
    with database.session_factory()() as db:
        threat_feeds.sync(db, only_due=False, client=transport())
        before = db.query(Indicator).filter(Indicator.source == "feed:malwarebazaar-recent").count()
        results = {r["id"]: r for r in threat_feeds.sync(db, only_due=False, client=transport(status=403))}
        assert "auth.abuse.ch" in results["malwarebazaar-recent"]["error"]
        assert db.query(Indicator).filter(Indicator.source == "feed:malwarebazaar-recent").count() == before
        empty = {r["id"]: r for r in threat_feeds.sync(db, only_due=False, client=transport(override={"stamparm/ipsum": "# nothing\n"}))}
        assert not empty["ipsum-3"]["ok"] and db.query(Indicator).filter(Indicator.source == "feed:ipsum-3").count() == 2


def test_auth_key_goes_to_abuse_ch_only(client):
    seen = []
    with database.session_factory()() as db:
        threat_feeds.sync(db, auth_key="k-123", only_due=False, client=transport(seen=seen))
    for url, headers in seen:
        assert (headers.get("auth-key") == "k-123") == ("abuse.ch" in url)


def test_turning_a_feed_off_removes_its_indicators(client, admin):
    with database.session_factory()() as db:
        threat_feeds.sync(db, only_due=False, client=transport())
    off = client.patch("/api/console/intel/feeds/feodo-c2", json={"enabled": False}, headers=admin).json()
    assert off["enabled"] is False and off["indicators"] == 0
    with database.session_factory()() as db:
        assert db.query(Indicator).filter(Indicator.source == "feed:feodo-c2").count() == 0
        assert db.get(IntelFeed, "feodo-c2").enabled is False
        results = threat_feeds.sync(db, only_due=False, client=transport())
        assert "feodo-c2" not in {r["id"] for r in results}
