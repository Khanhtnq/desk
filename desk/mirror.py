"""Every page as markdown, and /llms.txt.

Append `.md` to any page path (the home page is `/index.md`), or ask with `Accept: text/markdown`, and the
HTML the browser would get is converted on the way out: bar, footer, scripts, forms and the signer box are
dropped; headings, prose, tables, lists and links are kept. One converter, so every page present and
future has a markdown twin without a second template. `/llms.txt` is the reading list for agents.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from bs4 import BeautifulSoup
from markdownify import MarkdownConverter

from .config import Config

SKIP_PREFIXES = ("/v1", "/static", "/og")
DROP = ("script", "style", "template", "form", "button", "input", "textarea", "select", "noscript", "dialog")
DROP_CLASSES = ("keybox",)


# ---- paths ------------------------------------------------------------------------------------------


def md_target(path: str) -> str | None:
    """The page a `.md` path mirrors, or None when the path is not a markdown request."""
    if not path.endswith(".md") or path.startswith(SKIP_PREFIXES):
        return None
    page = path[:-3]
    return "/" if page in ("", "/index") else page


def md_path(page: str) -> str:
    """The `.md` twin of a page path."""
    return "/index.md" if page in ("", "/") else page.rstrip("/") + ".md"


def wants_markdown(accept: str) -> bool:
    """True for a client that asked for markdown and did not also ask for HTML (browsers always do)."""
    a = (accept or "").lower()
    return "text/markdown" in a and "text/html" not in a


# ---- conversion -------------------------------------------------------------------------------------

class _Converter(MarkdownConverter):
    """Text is text. Everything the HTML page showed as characters stays characters in the twin: markdown
    punctuation, `<`, `&` and `[` in user-written text are backslash-escaped, and a preformatted block is
    fenced with more backticks than any run inside it, so a report title, reply or note cannot add links,
    images, headings or raw HTML to the page under the desk's name (XE-0507)."""

    def convert_pre(self, el, text, parent_tags):
        if not text:
            return ""
        longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
        fence = "`" * max(3, longest + 1)
        return f"\n\n{fence}\n{text.strip(chr(10))}\n{fence}\n\n"


_converter = _Converter(
    heading_style="ATX",
    bullets="-",
    escape_underscores=True,
    escape_asterisks=True,
    escape_misc=True,
    table_infer_header=True,
)


def html_to_markdown(html: str, canonical: str) -> str:
    """The `<main>` of a rendered page as markdown, with a line saying where it came from."""
    soup = BeautifulSoup(html, "html.parser")
    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    main = soup.find("main") or soup.body or soup
    for tag in main.find_all(DROP):
        tag.decompose()
    for cls in DROP_CLASSES:
        for tag in main.find_all(class_=cls):
            tag.decompose()
    # diagrams: keep what they say, not how they draw it
    for svg in main.find_all("svg"):
        label = svg.get("aria-label")
        rep = soup.new_tag("p")
        if label:
            em = soup.new_tag("em")
            em.string = label
            rep.append(em)
        svg.replace_with(rep)
    # <details><summary>: the question as a bold line, the answer below it
    for summ in main.find_all("summary"):
        p = soup.new_tag("p")
        strong = soup.new_tag("strong")
        strong.string = summ.get_text(" ", strip=True)
        p.append(strong)
        summ.replace_with(p)
    # relative links become absolute so the file reads the same anywhere
    root = canonical.split("/", 3)
    origin = "/".join(root[:3]) if len(root) >= 3 else ""
    for a in main.find_all("a", href=True):
        href = a["href"]
        if href.startswith("/") and not href.startswith("//"):
            a["href"] = origin + href
    body = _converter.convert_soup(main)
    body = re.sub(r"[ \t]+\n", "\n", body)
    body = re.sub(r"\n{3,}", "\n\n", body).strip()
    head = f"*Markdown view of <{canonical}>. The page is the record; this is the same page for reading.*"
    if title:
        # the title is page-controlled text; it must not be able to close the comment it sits in
        head = f"<!-- {title.replace('--', '- -').replace('>', '›')} -->\n{head}"
    return f"{head}\n\n{body}\n"


# ---- middleware -------------------------------------------------------------------------------------


class MarkdownMirror:
    """Pure ASGI. Rewrites `/x.md` to `/x`, lets the app render, converts text/html answers to markdown."""

    def __init__(self, app, base_url: str | Callable[[], str] = ""):
        self.app = app
        self._base_url = base_url

    @property
    def base_url(self) -> str:
        b = self._base_url() if callable(self._base_url) else self._base_url
        return (b or "").rstrip("/")

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("method") not in ("GET", "HEAD"):
            return await self.app(scope, receive, send)
        path = scope["path"]
        target = md_target(path)
        if target is None:
            if path.startswith(SKIP_PREFIXES):
                return await self.app(scope, receive, send)
            accept = next((v.decode("latin-1") for k, v in scope.get("headers", []) if k == b"accept"), "")
            if not wants_markdown(accept):
                return await self.app(scope, receive, send)
            target = path
        scope = {**scope, "path": target, "raw_path": target.encode()}

        status = 200
        headers: list[tuple[bytes, bytes]] = []
        body = bytearray()

        async def capture(message):
            nonlocal status, headers
            if message["type"] == "http.response.start":
                status = message["status"]
                headers = list(message.get("headers", []))
            elif message["type"] == "http.response.body":
                body.extend(message.get("body", b""))

        await self.app(scope, receive, capture)

        ctype = next((v for k, v in headers if k == b"content-type"), b"").decode("latin-1")
        if not ctype.startswith("text/html"):
            # not a page (a redirect, say): hand through what came back
            await send({"type": "http.response.start", "status": status, "headers": headers})
            await send({"type": "http.response.body", "body": bytes(body)})
            return

        base = self.base_url or _origin_from_scope(scope)
        out = html_to_markdown(body.decode("utf-8", "replace"), base + target).encode("utf-8")
        keep = [(k, v) for k, v in headers if k not in (b"content-type", b"content-length", b"vary")]
        keep += [
            (b"content-type", b"text/markdown; charset=utf-8"),
            (b"content-length", str(len(out)).encode()),
            (b"vary", b"Accept"),
        ]
        await send({"type": "http.response.start", "status": status, "headers": keep})
        await send({"type": "http.response.body", "body": out if scope["method"] == "GET" else b""})


def _origin_from_scope(scope) -> str:
    host = next((v.decode("latin-1") for k, v in scope.get("headers", []) if k == b"host"), "localhost")
    return f"{scope.get('scheme', 'http')}://{host}"


# ---- llms.txt ---------------------------------------------------------------------------------------


def build_llms_txt(
    cfg: Config, base_url: str, network_id: str, *, site: str = "bounty", other: str = ""
) -> str:
    """The reading list, per llmstxt.org: an H1, a blockquote summary, then sections of links. One per
    front door: the bounty's lists the programme pages, the support site's only what it has."""
    b = base_url.rstrip("/")
    copy = cfg.copy_public

    def link(path: str, text: str, note: str = "") -> str:
        tail = f": {note}" if note else ""
        return f"- [{text}]({b}{path}){tail}"

    common_api = [
        "## API",
        link("/v1", "Manifest", "JSON index of every endpoint, keys and config hashes"),
        link("/v1/openapi.json", "OpenAPI", "the schema"),
        link("/v1/log/head", "Log head", "the current tip of the log"),
        link("/v1/log/verify", "Log verify", "walks the chain and reports"),
        link("/v1/events?since=-1", "Events", "the log from an index; `/v1/events/stream` for SSE"),
        "",
        "## For agents",
        link("/v1/agent/brief.md", "The brief", "read this first: the role, the loop, the vocabularies, the rules"),
        "- `GET /v1/me`: who you are, your scopes, your owner's standing instructions",
        "- `POST /v1/tickets/{id}/notes`: an internal note (scope `write:notes`)",
        "- `POST /v1/tickets/{id}/proposals`: `{field, value, reason}`; a person adopts or rejects (scope `write:proposals`)",
        "- `POST /v1/tickets/{id}/patch-refs`: link a PR or commit (scope `write:patch-refs`)",
        "- No scope sends a reply, sets a status or an award, or reads a payout address.",
        "",
    ]
    how = (
        f"Network `{network_id}`. Every page here is also markdown: append `.md` to its path (the home page "
        "is `/index.md`), or request it with `Accept: text/markdown`. The JSON API lives under `/v1`; `GET /v1` "
        "lists it. Agents write with a bearer token: notes, proposals and patch links. People decide and reply."
    )

    if site == "support":
        sc = copy.get("support") or {}
        return "\n".join(
            [
                f"# {copy.get('support_name', 'XE Support')}",
                "",
                f"> {sc.get('headline', '')} {sc.get('sub', '')}".strip(),
                "",
                how,
                "",
                "## Start here",
                link("/ask", "Ask a question", "sign in and ask; the answer is public and stays"),
                link("/index.md", "Questions", "everything asked and answered, most recently answered first"),
                *[
                    link(f"/index.md?area={k}", v, (sc.get("topics") or {}).get(k, ""))
                    for k, v in cfg.topics.items()
                    if k != "other"
                ],
                link("/log.md", "Log", "the hash-chained public log of everything the desk does"),
                link("/live", "Live", "the log as it happens; `/v1/events/stream` is the stream itself"),
                "",
                "## Tickets",
                link(
                    "/XS-0001.md",
                    "A ticket",
                    "the question, the answer, the public thread; replace the id",
                ),
                link("/v1/tickets?kind=support&status=all", "Tickets JSON", "the same list, filterable"),
                f"- {sc.get('safety_lead', '')} {sc.get('safety', '')}".strip(),
                "",
                *common_api,
                "## Optional",
                f"- [Bug bounty]({other}): security bugs are reported there, not here" if other else "",
                "- [xe.network](https://xe.network): the network this serves",
                "",
            ]
        )

    return "\n".join(
        [
            f"# {copy.get('bounty_name', copy.get('site_name', 'XE Desk'))}",
            "",
            f"> {copy.get('headline', '')} {copy.get('sub', '')}".strip(),
            "",
            how,
            "",
            "## Start here",
            link("/report", "Report a bug", "sign in (GitHub, or a key of your own) and file; private by default"),
            link("/index.md", "Open tickets", "every public report, most severe first"),
            link(
                "/scope.md",
                "Scope and tiers",
                "what is in scope, the tiers and their ceilings, how disclosure works",
            ),
            link("/leaderboard.md", "Leaderboard", "awards so far, by reporter"),
            link("/log.md", "Log", "the hash-chained public log of everything the desk does"),
            link("/live", "Live", "the log as it happens; `/v1/events/stream` is the stream itself"),
            "",
            "## Tickets",
            link("/XE-0001.md", "A ticket", "facts, patches, and the public thread; replace the id"),
            link("/v1/tickets?kind=bounty&status=open", "Tickets JSON", "the same list, filterable"),
            link("/v1/export/triage.md", "Triage export", "the whole desk as the triage tables"),
            "",
            *common_api,
            "## Optional",
            "- [xe.network](https://xe.network): the network this serves",
            "- [xeprotocol/xe](https://github.com/xeprotocol/xe/issues): public reports filed there are read too",
            "",
        ]
    )
