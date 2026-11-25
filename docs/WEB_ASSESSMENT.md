# Web application assessment (VULN-08)

**Vulnerabilities → Web app assessment** assesses a website on one of a customer's external assets. The asset is one
whose ownership the customer attested when it was added. The code is in `cloud/fenrir_cloud/web_assessment.py`.

## What it does and does not do

* Sends only GET requests, to the attested host only. Before every request, the host's addresses are checked to be
  public.
* Never submits forms, never sends exploit payloads, never guesses passwords.
* Crawls on the same scheme, host and port, and respects `robots.txt` `Disallow` lines for all user agents.
* Is limited by four settings, and the limits used are recorded with the results:

  | Setting | Default |
  |---|---|
  | Pages | 50 |
  | Depth | 3 |
  | Delay between requests | 0.2 s |
  | Time budget | 120 s |

* Follows redirects only within the same host. A redirect from HTTP to HTTPS on that host is followed.

## Profiles

**Passive** reads what the site returns:
* headers and cookies;
* pages, scripts and forms;
* a short list of well-known exposed files (`.git`, `.env`, `.DS_Store`, server status, `phpinfo`, `.svn`,
  `backup.sql`).

A random missing page is requested first to detect "soft 404" sites, so that a site returning 200 for everything is
not reported as exposing files.

**Standard** adds two harmless probes:
* a random marker in a query parameter, to see whether it is echoed back unencoded;
* a made-up `Origin` header, to see whether CORS trusts any origin.

Either profile can send an `Authorization` or `Cookie` header, to assess pages behind sign-in. Adding one requires
step-up authentication. The value is stored encrypted only until the run ends, and is never logged or returned.

## Findings

| Status | Meaning | Examples |
|---|---|---|
| **Confirmed** | The response proves it. | Missing security headers or HSTS; version banners; cookies without Secure, HttpOnly or SameSite; directory listing; plain HTTP with no move to HTTPS; password forms over HTTP; exposed files matching their known content; third-party scripts without Subresource Integrity; CORS trusting any origin. |
| **Suspected** | A person should check it. | An echoed marker; outdated library versions in script addresses; error pages with stack traces; an exposed-file address answering 200 without the expected content. |

Each finding records:
* the request;
* the response status;
* an evidence excerpt;
* its OWASP Top 10 (2021) category, with advice.

## Not tested

These categories are always listed as not tested, with the reason:
* A04 insecure design;
* A09 logging and monitoring;
* A10 server-side request forgery;
* password guessing and session attacks (A07).

Also listed, depending on the run:
* access control between users (A01), when the run is unauthenticated;
* injection (A03), when the profile is passive.
