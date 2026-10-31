"""Every API call written in the console source reaches a real cloud route with that method, so no button or page in
the console calls something the server does not have. Calls whose path or method is only known at run time (a variable
prefix, a computed method) cannot be checked statically and are skipped."""

import re
from pathlib import Path

CONSOLE = Path(__file__).resolve().parents[2] / "console" / "src"
CALL = re.compile(r"\b(api|useData|useListData|fetch)\s*(?:<[^>()]*>)?\s*\(")
PLACEHOLDER = "\x00"


def _string(text: str, i: int) -> tuple[str, int]:
    quote, j, out = text[i], i + 1, []
    while j < len(text) and text[j] != quote:
        if text[j] == "\\":
            out.append(text[j + 1])
            j += 2
            continue
        if quote == "`" and text[j:j + 2] == "${":
            depth, k = 1, j + 2
            while depth and k < len(text):
                depth += {"{": 1, "}": -1}.get(text[k], 0)
                k += 1
            out.append(PLACEHOLDER)
            j = k
            continue
        out.append(text[j])
        j += 1
    return "".join(out), j + 1


def _first_argument(text: str, start: int) -> tuple[str | None, int]:
    """The path argument with expressions as placeholders; None when it is not built from literals (a variable, a ternary)."""
    i, depth, parts, saw_literal, in_expression = start, 0, [], False, False
    while i < len(text):
        c = text[i]
        if c in "\"'`" and depth == 0:
            value, i = _string(text, i)
            parts.append(value)
            saw_literal, in_expression = True, False
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif depth == 0 and c == ",":
            break
        elif depth == 0 and c == "?" and text[i + 1] != ".":
            return None, i  # cond ? a : b
        elif depth == 0 and c == "+":
            in_expression = False
        elif depth == 0 and not c.isspace() and not in_expression:
            parts.append(PLACEHOLDER)
            in_expression = True
        i += 1
    return ("".join(parts) if saw_literal else None), i


def _options(text: str, start: int) -> str:
    depth, i = 1, start
    while i < len(text) and depth:
        depth += {"(": 1, ")": -1}.get(text[i], 0)
        i += 1
    return text[start:i]


def console_calls():
    for path in sorted(CONSOLE.rglob("*.ts*")):
        text = path.read_text()
        for match in CALL.finditer(text):
            kind = match.group(1)
            url, end = _first_argument(text, match.end())
            if url is None or url.startswith(PLACEHOLDER):
                continue
            if kind == "fetch" and not url.startswith(("/api/", "/dns/")):
                continue
            rest = text[end:end + 1 + len(_options(text, end + 1))] if end < len(text) and text[end] == "," else ""
            method = "GET"
            if kind in ("api", "fetch") and rest:
                options = rest.lstrip(", \n")
                if not options.startswith("{"):
                    continue  # options built by a function: not checkable here
                literal = re.match(r"\{[^{}]*?\bmethod:\s*\"(\w+)\"", options)
                if re.search(r"\bmethod:", options) and not literal:
                    continue  # method chosen at run time
                if literal:
                    method = literal.group(1)
                elif re.match(r"\{\s*(body\b|[^{}]*\bbody\s*[:,}])", options):
                    method = "POST"
            full = url if url.startswith("/") else "/api/console/" + url
            full = full.split("?")[0]
            line = text[:match.start()].count("\n") + 1
            yield f"{path.relative_to(CONSOLE)}:{line}", method, full


def routes(app):
    found = []

    def walk(items, prefix=""):
        for route in items:
            if type(route).__name__ == "_IncludedRouter":
                walk(route.original_router.routes, prefix + route.include_context.prefix)
            elif hasattr(route, "path"):
                full = prefix + route.path
                found.append((full, re.compile("^" + re.sub(r"\{[^}]+\}", "[^/]+", full) + "$"), getattr(route, "methods", None) or set()))

    walk(app.routes)
    return found


def test_every_console_api_call_has_a_cloud_route(client):
    table = routes(client.app)
    calls = list(console_calls())
    assert len(calls) > 300  # the scan is reading the console
    def reaches(url: str, template: str, rx) -> bool:
        # A console placeholder (${...}) can stand for an id or for a fixed word such as "approve".
        console_rx = re.compile("^" + "[^/]+".join(re.escape(part) for part in url.split(PLACEHOLDER)) + "$")
        return bool(rx.match(url.replace(PLACEHOLDER, "x")) or console_rx.match(template))

    missing = [f"{where} {method} {url.replace(PLACEHOLDER, '${…}')}" for where, method, url in calls
               if not any(method in methods and reaches(url, template, rx) for template, rx, methods in table)]
    assert missing == []
