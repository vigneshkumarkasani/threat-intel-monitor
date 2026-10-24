"""
Threat Intel Monitor
====================
Watches news sites, research blogs, vendor advisories, CISA and social media
for new CVEs and malware, and reports them on Telegram within minutes:

  * INSTANT ALERTS (every run, every 5 minutes on GitHub Actions)
      🔴 a CVE newly added to CISA's Known Exploited Vulnerabilities catalog
      🦠 a CVE linked to malware or a named malware family
      🛑 / ⚠️ a CVE reported as exploited (by a vendor, or in news/research)
      🆕 the first time a CVE appears in any news, research or vendor source
      📰 a malware article, even if it names no CVE
    A CVE is alerted again only when its news gets more serious
    (new CVE -> exploited -> malware -> KEV), so one story copied by ten
    sites sends one alert. Social posts alert only on exploitation/malware.
  * DAILY DIGEST (once a day, at DIGEST_TIME_IST)
      everything from the last 24 hours, grouped by CVE, with CVSS, EPSS,
      KEV status, named malware and how many sources reported it

Sources live in sources.json and malware names in malware_names.txt.
What has already been seen is remembered in seen.json.

Settings come from environment variables (GitHub "secrets"):
  TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID   required to send messages
  NVD_API_KEY                            optional, faster CVSS lookups (free)
  BLUESKY_HANDLE, BLUESKY_APP_PASSWORD   optional, turns on Bluesky search (free)
  X_BEARER_TOKEN                         optional, turns on X/Twitter search (paid)
  FORCE_DIGEST                           "true" sends the digest right now
Without the Telegram settings the script runs in DRY-RUN mode and prints
the messages instead of sending them.

Uses only Python's standard library: nothing to install.
"""

import html
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Settings you might want to change
# ---------------------------------------------------------------------------

DIGEST_TIME_IST = "09:00"        # when the daily digest is sent (India time)
MAX_INSTANT_ALERTS_PER_RUN = 30  # stops a flood of messages on a busy day
MAX_DIGEST_LOOKUPS = 40          # most CVEs to look up in NVD per digest
FINDINGS_KEPT_DAYS = 7           # how long findings are kept for the digest
ALERT_REPEAT_DAYS = 14           # don't re-alert the same CVE for the same reason
NEARBY_SENTENCES = 2             # how far from a CVE mention to look for malware words

# Words that mean "this is about malware or an attack campaign".
MALWARE_WORDS = [
    "malware", "ransomware", "botnet", "backdoor", "backdoors", "trojan",
    "stealer", "infostealer", "loader", "dropper", "cryptominer", "crypto miner",
    "coinminer", "cryptojacking", "webshell", "webshells", "web shell",
    "web shells", "rootkit", "bootkit", "spyware", "wiper", "rat",
    "implant", "implants", "command-and-control", "c2 server",
]

# Phrases that mean "attackers are already using this bug". Includes the
# wording vendors use in their own advisories.
EXPLOIT_WORDS = [
    "actively exploited", "exploited in the wild", "in-the-wild",
    "in the wild", "zero-day", "0-day", "zero day", "under attack",
    "under active attack", "exploitation attempts", "active exploitation",
    "being exploited", "exploited in attacks", "exploited as a zero-day",
    "mass exploitation", "observed exploitation", "exploitation observed",
    "exists in the wild",                                   # Google Chrome
    "aware of exploitation", "aware of attempted exploitation",
    "aware of successful exploitation", "aware of limited exploitation",
    "aware of active exploitation",                         # Cisco, Palo Alto
    "reported to be exploited", "has been exploited",       # Fortinet
    "known exploited", "added to kev", "kev catalog",
]

HERE = Path(__file__).parent
STATE_FILE = HERE / "seen.json"
SOURCES_FILE = HERE / "sources.json"
MALWARE_FILE = HERE / "malware_names.txt"

IST = timezone(timedelta(hours=5, minutes=30))
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
USER_AGENT = "Mozilla/5.0 (compatible; ThreatIntelMonitor/2.0; +https://github.com)"
CONFIRMED_TYPES = {"vendor", "government"}  # an exploitation claim from these counts as confirmed
KIND_RANK = {"cve": 0, "exploited": 1, "malware": 2, "kev": 3}


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def now_utc():
    return datetime.now(timezone.utc)


def log(message):
    print(f"[{now_utc():%Y-%m-%d %H:%M:%S} UTC] {message}", flush=True)


def fetch(url, timeout=30, data=None, headers=None):
    """Download a URL and return the raw bytes."""
    request = urllib.request.Request(url, data=data,
                                     headers={"User-Agent": USER_AGENT, **(headers or {})})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def phrase_regex(phrases, case_sensitive=False):
    """One regex that matches any phrase as whole words (longest first)."""
    escaped = sorted((re.escape(p) for p in phrases if p), key=len, reverse=True)
    if not escaped:
        return re.compile(r"(?!x)x")  # matches nothing
    flags = 0 if case_sensitive else re.IGNORECASE
    return re.compile(r"(?<![\w-])(" + "|".join(escaped) + r")(?![\w-])", flags)


def load_malware_names():
    if not MALWARE_FILE.exists():
        return []
    names = []
    for line in MALWARE_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            names.append(line)
    return names


MALWARE_RE = phrase_regex(MALWARE_WORDS)
EXPLOIT_RE = phrase_regex(EXPLOIT_WORDS)
MALWARE_NAMES = load_malware_names()
MALWARE_NAME_RE = phrase_regex(MALWARE_NAMES)
CANONICAL_NAME = {n.lower(): n for n in MALWARE_NAMES}


def strip_html(text):
    """HTML to plain text, keeping paragraph breaks as blank lines."""
    text = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", text or "")
    text = re.sub(r"(?i)<\s*(br|/?p|/li|/?h\d|/?div|/?ul|/?ol|/?table|/tr|/blockquote)\b[^>]*>", "\n\n", text)
    text = html.unescape(re.sub(r"<[^>]+>", " ", text))
    paragraphs = (re.sub(r"\s+", " ", p).strip() for p in re.split(r"\n\s*\n", text))
    return "\n\n".join(p for p in paragraphs if p)


def sentences(paragraph):
    return [s for s in re.split(r"(?<=[.!?])\s+", paragraph) if s]


def esc(text):
    return html.escape(str(text or ""), quote=False)


def nvd_link(cve_id):
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}"


def cve_link(cve_id):
    return f'<a href="{nvd_link(cve_id)}">{cve_id}</a>'


def parse_time(value):
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Saved state (seen.json)
# ---------------------------------------------------------------------------

def load_state():
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            log("seen.json was unreadable, starting fresh")
    return {}


def save_state(state):
    state.pop("_seen_set", None)
    cutoff_findings = now_utc() - timedelta(days=FINDINGS_KEPT_DAYS)
    cutoff_alerts = now_utc() - timedelta(days=ALERT_REPEAT_DAYS)
    state["articles"] = state.get("articles", [])[-6000:]
    state["findings"] = [f for f in state.get("findings", [])
                         if (parse_time(f.get("time")) or now_utc()) > cutoff_findings]
    state["alerted"] = {k: v for k, v in state.get("alerted", {}).items()
                        if (parse_time(v) or now_utc()) > cutoff_alerts}
    state["nvd_cache"] = dict(list(state.get("nvd_cache", {}).items())[-500:])
    state["last_run"] = now_utc().isoformat(timespec="seconds")
    STATE_FILE.write_text(json.dumps(state, indent=1, sort_keys=True), encoding="utf-8")


# ---------------------------------------------------------------------------
# Source 1: CISA KEV
# ---------------------------------------------------------------------------

def check_kev(state, kev_url, run_id):
    """Record new KEV entries as findings. Returns the full KEV lookup table."""
    data = json.loads(fetch(kev_url, timeout=60))
    entries = data.get("vulnerabilities", [])
    log(f"KEV catalog has {len(entries)} entries")
    kev = {e["cveID"].upper(): e for e in entries if e.get("cveID")}

    first_run = "kev" not in state
    seen = set(state.get("kev", []))
    state["kev"] = sorted(seen | set(kev))
    if first_run:
        log("KEV: first run, saved the current list without alerting")
        return kev

    new_ids = sorted((c for c in kev if c not in seen), key=lambda c: kev[c].get("dateAdded", ""))
    for cve in new_ids:
        e = kev[cve]
        state["findings"].append({
            "cve": cve, "kind": "kev", "source": "CISA KEV", "source_type": "government",
            "title": e.get("vulnerabilityName", ""),
            "link": nvd_link(cve), "malware": [], "terms": [],
            "ransomware": e.get("knownRansomwareCampaignUse", "Unknown").lower() == "known",
            "summary": e.get("shortDescription", "")[:500],
            "time": now_utc().isoformat(timespec="seconds"), "run": run_id,
        })
    log(f"KEV: {len(new_ids)} new entries")
    return kev


# ---------------------------------------------------------------------------
# Source 2: news, research, vendor and government feeds
# ---------------------------------------------------------------------------

def _items_from_tree(root):
    atom = "{http://www.w3.org/2005/Atom}"
    content_ns = "{http://purl.org/rss/1.0/modules/content/}encoded"
    items = []
    for item in root.iter("item"):                                   # RSS 2.0
        body = item.findtext(content_ns) or item.findtext("description") or ""
        items.append(((item.findtext("title") or "").strip(),
                      (item.findtext("link") or item.findtext("guid") or "").strip(), body))
    for entry in root.iter(f"{atom}entry"):                          # Atom
        link = ""
        for link_el in entry.findall(f"{atom}link"):
            if link_el.get("rel", "alternate") == "alternate":
                link = link_el.get("href", "").strip()
                break
        body = entry.findtext(f"{atom}content") or entry.findtext(f"{atom}summary") or ""
        items.append(((entry.findtext(f"{atom}title") or "").strip(), link, body))
    return items


def _tag_text(block, *tags):
    """Text of the first of these tags in a chunk of feed text (handles CDATA)."""
    for tag in tags:
        m = re.search(rf"<{tag}(?:\s[^>]*)?>(.*?)</{tag}>", block, re.S | re.I)
        if m:
            value = m.group(1).strip()
            cdata = re.fullmatch(r"<!\[CDATA\[(.*)\]\]>", value, re.S)
            return cdata.group(1) if cdata else html.unescape(value)
    return ""


def _items_by_pattern(text):
    """Last resort for badly broken feeds: pull items out with simple patterns."""
    items = []
    for block in re.findall(r"<item[\s>].*?</item>", text, re.S | re.I):
        items.append((_tag_text(block, "title").strip(),
                      _tag_text(block, "link", "guid").strip(),
                      _tag_text(block, "content:encoded", "description")))
    for block in re.findall(r"<entry[\s>].*?</entry>", text, re.S | re.I):
        link = re.search(r'<link[^>]*href="([^"]+)"', block)
        items.append((_tag_text(block, "title").strip(), link.group(1) if link else "",
                      _tag_text(block, "content", "summary")))
    return items


def parse_feed(raw):
    """
    Return [(title, link, text)] from an RSS or Atom feed, using full content when given.
    Many real feeds contain small mistakes (a stray "&", control characters), so if the
    strict reader refuses a feed it is cleaned up, and failing that read item by item.
    """
    text = raw.decode("utf-8", errors="replace").lstrip("\ufeff \r\n\t")
    head = text[:600].lower()
    if ("<html" in head or "<!doctype html" in head) and "<rss" not in head and "<feed" not in head:
        raise ValueError("got a web page instead of a feed (the site may be blocking automated readers)")
    try:
        return _items_from_tree(ET.fromstring(raw))
    except ET.ParseError:
        pass
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", text)
    cleaned = re.sub(r"&(?!(?:[a-zA-Z][a-zA-Z0-9]*|#[0-9]+|#x[0-9a-fA-F]+);)", "&amp;", cleaned)
    cleaned = re.sub(r"^<\?xml[^>]*\?>", "", cleaned)  # str input can't carry an encoding declaration
    try:
        return _items_from_tree(ET.fromstring(cleaned))
    except ET.ParseError:
        pass
    items = _items_by_pattern(text)
    if not items:
        raise ValueError("feed could not be read, even item by item")
    return items


# "No evidence it was exploited in the wild", "not in the KEV catalog" ...
NEGATION_RE = re.compile(
    r"\bno (known |public |active |confirmed )?(evidence|sign|signs|indication|indications|reports?|"
    r"exploitation|attacks?|knowledge|information)\b"
    r"|\bnot (yet |been |currently |known |aware|listed|seen|observed|exploited|included|in (the )?(cisa|kev))"
    r"|\b(has|have|had|is|are|was|were)n't\b|\b(has|have|is|are|was|were) not\b"
    r"|\bnever (been )?(exploited|seen|observed)\b|\bunaware\b|\bwithout (any )?evidence\b"
    r"|\bunexploited\b", re.IGNORECASE)
# "could let an attacker install malware" describes impact, not a real campaign.
HYPOTHETICAL_RE = re.compile(
    r"\b(could|may|might|would|potentially|possible|possibly|can be used|allow(s|ing)? "
    r"(an )?(attacker|attackers|threat actors?) to|if exploited)\b", re.IGNORECASE)


def sentence_signals(sentence):
    """Return (generic malware words, exploitation phrases, named families) for one sentence."""
    malware = {m.lower() for m in MALWARE_RE.findall(sentence)}
    exploit = {m.lower() for m in EXPLOIT_RE.findall(sentence)}
    names = {CANONICAL_NAME.get(m.lower(), m) for m in MALWARE_NAME_RE.findall(sentence)}
    if exploit and NEGATION_RE.search(sentence):
        exploit = set()
    if malware and (HYPOTHETICAL_RE.search(sentence) or NEGATION_RE.search(sentence)):
        malware = set()
    return malware, exploit, names


def analyse_article(title, body):
    """
    Work out which CVEs an article ties to malware or exploitation.

    Words in the title apply to every CVE in the article. Words in the body
    only count if they're within NEARBY_SENTENCES of where the CVE is
    mentioned, so a "related story" about ransomware at the bottom of a page
    doesn't get pinned to an unrelated CVE.
    Returns {cve: {"malware": set, "terms": set, "names": set}}.
    """
    # (paragraph number, sentence) pairs; nearby words never cross a paragraph break
    parts = [(n, s) for n, para in enumerate(strip_html(body).split("\n\n")) for s in sentences(para)]
    t_malware, t_exploit, t_names = sentence_signals(title)

    results = {}
    for cve in {c.upper() for c in CVE_PATTERN.findall(title)}:
        results[cve] = {"malware": set(t_malware), "terms": set(t_exploit), "names": set(t_names)}

    signals = [sentence_signals(s) for _, s in parts]
    for i, (para, sentence) in enumerate(parts):
        found = {c.upper() for c in CVE_PATTERN.findall(sentence)}
        if not found:
            continue
        window = [signals[j] for j in range(max(0, i - NEARBY_SENTENCES),
                                            min(len(parts), i + NEARBY_SENTENCES + 1))
                  if parts[j][0] == para]
        malware = set().union(*(w[0] for w in window)) | t_malware
        exploit = set().union(*(w[1] for w in window)) | t_exploit
        names = set().union(*(w[2] for w in window)) | t_names
        for cve in found:
            r = results.setdefault(cve, {"malware": set(), "terms": set(), "names": set()})
            r["malware"] |= malware
            r["terms"] |= exploit
            r["names"] |= names

    return results


def classify(r):
    """Which kind of finding a CVE result is: malware > exploited > plain cve."""
    if r["malware"] or r["names"]:
        return "malware"  # a named family counts even without a generic word
    if r["terms"]:
        return "exploited"
    return "cve"


def title_is_malware_news(title):
    """True when a headline is about malware or a named family (used for articles with no CVE)."""
    malware, _, names = sentence_signals(title)
    return bool(malware or names)


def make_summary(title, body, limit=500):
    """The first sentences of an article (skipping a repeat of the headline), up to `limit` characters."""
    text = strip_html(body).replace("\n\n", " ").strip()
    if title and text.lower().startswith(title.lower().rstrip("…")):
        text = text[len(title.rstrip("…")):].lstrip(" .:-–—")
    text = re.sub(r"\s*(The post .{0,200} appeared first on .{0,100}|Read more|Continue reading)\.?\s*$", "", text)
    out = ""
    for sentence in sentences(text):
        if len(out) + len(sentence) + 1 > limit:
            break
        out += (" " if out else "") + sentence
    if not out and text:
        out = text[:limit - 1].rsplit(" ", 1)[0] + "…"
    return out


def record_item(state, source, source_type, title, link, body, run_id):
    """Turn one article, advisory or post into findings. Returns how many were added."""
    social = source_type == "social"
    if not title:  # social posts have no headline: use the start of the text
        text = strip_html(body).replace("\n\n", " ")
        title = text[:140] + ("…" if len(text) > 140 else "")
    added = 0
    summary = make_summary(title, body)
    results = analyse_article(title, body)
    for cve, r in results.items():
        kind = classify(r)
        if social and kind == "cve":
            continue  # social: only exploitation/malware posts (bots announce every CVE)
        state["findings"].append({
            "cve": cve, "kind": kind, "source": source, "source_type": source_type,
            "title": title, "link": link,
            "malware": sorted(r["names"]), "terms": sorted(r["malware"] | r["terms"]),
            "summary": summary,
            "time": now_utc().isoformat(timespec="seconds"), "run": run_id,
        })
        added += 1
    if not results and not social and title_is_malware_news(title):
        _, _, names = sentence_signals(title + ". " + strip_html(body)[:2000])
        state["findings"].append({
            "cve": None, "kind": "malware_news", "source": source, "source_type": source_type,
            "title": title, "link": link, "malware": sorted(names), "terms": [],
            "summary": summary,
            "time": now_utc().isoformat(timespec="seconds"), "run": run_id,
        })
        added += 1
    return added


def check_feeds(state, feeds, run_id):
    seen = set(state.get("articles", []))
    remembered = list(state.get("articles", []))
    feeds_read = set(state.get("feeds_read", []))
    reached = 0

    for feed in feeds:
        name, url, kind = feed["name"], feed["url"], feed.get("type", "news")
        try:
            items = parse_feed(fetch(url))
        except (urllib.error.URLError, ET.ParseError, TimeoutError, OSError, ValueError) as err:
            log(f"Could not read {name}: {err}")
            continue
        reached += 1
        first_read = name not in feeds_read
        feeds_read.add(name)
        new_matches = 0

        for title, link, body in items:
            if not link or link in seen:
                continue
            seen.add(link)
            remembered.append(link)
            if first_read:
                continue  # remember the backlog, don't report it
            new_matches += record_item(state, name, kind, title, link, body, run_id)
        note = " (first read: saved without alerts)" if first_read else ""
        log(f"{name}: {len(items)} items, {new_matches} new CVE matches{note}")

    state["articles"] = remembered
    state["feeds_read"] = sorted(feeds_read)
    return reached


# ---------------------------------------------------------------------------
# Optional social sources: Bluesky (free login) and X/Twitter (paid API)
# ---------------------------------------------------------------------------

def remember_post(state, link, source):
    """True if this post is new. The first time a source is read, only remember."""
    seen = state.setdefault("_seen_set", set(state.get("articles", [])))
    if link in seen:
        return False
    seen.add(link)
    state["articles"].append(link)
    return source in state.get("feeds_read", [])


def check_bluesky(state, config, run_id):
    handle = os.environ.get("BLUESKY_HANDLE", "").strip()
    password = os.environ.get("BLUESKY_APP_PASSWORD", "").strip()
    settings = config.get("bluesky", {})
    if not (handle and password and settings.get("queries")):
        return 0
    last = parse_time(state.get("bluesky_last"))
    if last and now_utc() - last < timedelta(minutes=settings.get("every_minutes", 15) - 1):
        return 0  # logins are rate-limited, so Bluesky is searched less often
    try:
        session = json.loads(fetch(
            "https://bsky.social/xrpc/com.atproto.server.createSession",
            data=json.dumps({"identifier": handle, "password": password}).encode(),
            headers={"Content-Type": "application/json"}))
        auth = {"Authorization": f"Bearer {session['accessJwt']}"}
    except Exception as err:
        log(f"Bluesky login failed: {err}")
        return 0
    state["bluesky_last"] = now_utc().isoformat(timespec="seconds")
    added = 0
    for query in settings["queries"]:
        url = ("https://bsky.social/xrpc/app.bsky.feed.searchPosts?sort=latest&limit="
               f"{settings.get('limit', 25)}&q=" + urllib.parse.quote(query))
        try:
            posts = json.loads(fetch(url, headers=auth)).get("posts", [])
        except Exception as err:
            log(f"Bluesky search '{query}' failed: {err}")
            continue
        for post in posts:
            rkey = post.get("uri", "").rsplit("/", 1)[-1]
            who = post.get("author", {}).get("handle", "")
            link = f"https://bsky.app/profile/{who}/post/{rkey}"
            if remember_post(state, link, "Bluesky"):
                added += record_item(state, f"Bluesky @{who}", "social", "",
                                     link, post.get("record", {}).get("text", ""), run_id)
    if "Bluesky" not in state["feeds_read"]:
        state["feeds_read"].append("Bluesky")
        log("Bluesky: first read, saved posts without alerts")
    log(f"Bluesky: {added} new CVE matches")
    return added


def check_x(state, config, run_id):
    token = os.environ.get("X_BEARER_TOKEN", "").strip()
    settings = config.get("x", {})
    if not (token and settings.get("query")):
        return 0
    today = now_utc().date().isoformat()
    usage = state.get("x_reads", {})
    if usage.get("date") != today:
        usage = {"date": today, "count": 0}
    remaining = settings.get("max_reads_per_day", 150) - usage["count"]
    want = min(settings.get("max_per_run", 20), remaining)
    if want < 10:  # X requires at least 10 results per request
        log("X: daily read budget used up, skipping until tomorrow (UTC)")
        return 0
    params = {"query": settings["query"], "max_results": str(min(want, 100)),
              "tweet.fields": "created_at", "expansions": "author_id", "user.fields": "username"}
    if state.get("x_since_id"):
        params["since_id"] = state["x_since_id"]
    url = "https://api.x.com/2/tweets/search/recent?" + urllib.parse.urlencode(params)
    try:
        data = json.loads(fetch(url, headers={"Authorization": f"Bearer {token}"}))
    except urllib.error.HTTPError as err:
        log(f"X search failed ({err.code}): {err.read().decode(errors='replace')[:300]}")
        return 0
    except Exception as err:
        log(f"X search failed: {err}")
        return 0
    tweets = data.get("data", [])
    users = {u["id"]: u.get("username", "") for u in data.get("includes", {}).get("users", [])}
    usage["count"] += len(tweets)
    state["x_reads"] = usage
    if data.get("meta", {}).get("newest_id"):
        state["x_since_id"] = data["meta"]["newest_id"]
    added = 0
    for t in tweets:
        who = users.get(t.get("author_id"), "i")
        link = f"https://x.com/{who}/status/{t['id']}"
        if remember_post(state, link, "X"):
            added += record_item(state, f"X @{who}", "social", "", link, t.get("text", ""), run_id)
    if "X" not in state["feeds_read"]:
        state["feeds_read"].append("X")
        log("X: first read, saved posts without alerts")
    log(f"X: {len(tweets)} posts read (today's total {usage['count']}), {added} new CVE matches")
    return added


# ---------------------------------------------------------------------------
# Enrichment: NVD (CVSS, product) and FIRST EPSS
# ---------------------------------------------------------------------------

def nvd_lookup(state, cve, api_key):
    cache = state.setdefault("nvd_cache", {})
    cached = cache.get(cve)
    if cached and (now_utc() - (parse_time(cached.get("time")) or now_utc())).days < 3:
        return cached
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + urllib.parse.quote(cve)
    headers = {"apiKey": api_key} if api_key else {}
    info = {"time": now_utc().isoformat(timespec="seconds")}
    try:
        data = json.loads(fetch(url, timeout=30, headers=headers))
        vulns = data.get("vulnerabilities", [])
        if vulns:
            c = vulns[0]["cve"]
            metrics = c.get("metrics", {})
            for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metrics.get(key):
                    m = metrics[key][0].get("cvssData", {})
                    info["cvss"] = m.get("baseScore")
                    info["severity"] = m.get("baseSeverity") or metrics[key][0].get("baseSeverity")
                    break
            desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
            info["description"] = desc[:300]
    except Exception as err:  # NVD is often slow; never let it break the digest
        log(f"NVD lookup failed for {cve}: {err}")
        return cached or {}
    cache[cve] = info
    time.sleep(0.7 if api_key else 6.5)  # NVD allows 5 requests per 30 s without a key
    return info


def epss_lookup(cves):
    scores = {}
    for i in range(0, len(cves), 50):
        batch = cves[i:i + 50]
        try:
            data = json.loads(fetch("https://api.first.org/data/v1/epss?cve=" + ",".join(batch)))
            for row in data.get("data", []):
                scores[row["cve"].upper()] = float(row.get("epss", 0))
        except Exception as err:
            log(f"EPSS lookup failed: {err}")
    return scores


# ---------------------------------------------------------------------------
# Building messages
# ---------------------------------------------------------------------------

MAX_ALERT_LOOKUPS = 30  # most CVEs to look up in NVD for instant alerts per run
DIVIDER = "━━━━━━━━━━━━━━━━━━"


def severity_of(cvss, given=None):
    if given:
        return given.title()
    if cvss is None:
        return None
    return "Critical" if cvss >= 9 else "High" if cvss >= 7 else "Medium" if cvss >= 4 else "Low"


SEVERITY_ICON = {"Critical": "🟥", "High": "🟧", "Medium": "🟨", "Low": "🟩"}


def found_time(f):
    t = parse_time(f.get("time")) or now_utc()
    return t.astimezone(IST).strftime("%d %b %Y, %I:%M %p IST").replace(" 0", " ").lstrip("0")


def score_line(cve, info, epss, kev):
    """'CVSS 9.9 (Critical) · EPSS 87.0% · in KEV' for one CVE."""
    bits = []
    if info.get("cvss") is not None:
        bits.append(f"CVSS {info['cvss']} ({severity_of(info['cvss'], info.get('severity'))})")
    else:
        bits.append("CVSS not published yet")
    bits.append(f"EPSS {epss[cve] * 100:.1f}%" if cve in epss else "EPSS n/a")
    bits.append("in KEV ✅" if cve in kev else "not in KEV")
    return " · ".join(bits)


def instant_alerts(state, kev, run_id, api_key=""):
    """Turn this run's new findings into Telegram messages (dicts with text and buttons)."""
    alerted = state.setdefault("alerted", {})
    fresh = [f for f in state["findings"] if f.get("run") == run_id]

    # --- 1) decide what to alert on -------------------------------------------------
    # A CVE is alerted again only when its news gets more serious:
    # plain CVE -> exploited -> malware -> KEV. Ten copies of one story send one alert.
    best = {}
    for key in alerted:
        cve, _, kind = key.partition("|")
        best[cve] = max(best.get(cve, -1), KIND_RANK.get(kind, 0))
    planned = []  # (kind of message, [findings])
    for f in (x for x in fresh if x["kind"] == "kev"):
        alerted[f"{f['cve']}|kev"] = f["time"]
        best[f["cve"]] = KIND_RANK["kev"]
        planned.append(("kev", [f]))
    by_article = {}
    for f in (x for x in fresh if x["kind"] != "kev"):
        by_article.setdefault(f["link"], []).append(f)
    for link, group in by_article.items():
        if group[0]["kind"] == "malware_news":
            planned.append(("malware_news", group[:1]))
            continue
        new = []
        for f in group:
            rank = KIND_RANK[f["kind"]]
            if rank > best.get(f["cve"], -1):
                new.append(f)
                best[f["cve"]] = rank
                alerted[f"{f['cve']}|{f['kind']}"] = f["time"]
        if new:
            planned.append(("article", new))

    # --- 2) look up CVSS and EPSS for the CVEs we're about to report -----------------
    cves = sorted({f["cve"] for _, group in planned for f in group if f.get("cve")})
    epss = epss_lookup(cves) if cves else {}
    info = {}
    for cve in cves[:MAX_ALERT_LOOKUPS]:
        info[cve] = nvd_lookup(state, cve, api_key)

    # --- 3) write the messages ------------------------------------------------------
    messages = []
    for kind, group in planned:
        if kind == "kev":
            messages.append(render_kev(group[0], kev, info, epss))
        elif kind == "malware_news":
            messages.append(render_malware_news(group[0]))
        else:
            top = max(KIND_RANK[f["kind"]] for f in group)
            if top == KIND_RANK["cve"]:
                messages.append(render_card(group, kev, info, epss))
            else:
                messages.append(render_detailed(group, top, kev, info, epss))
    return messages


def article_buttons(link, cves, kev, source_type="news"):
    label = "💬 Open post" if source_type == "social" else "📖 Read article"
    buttons = [(label, link)] if link.startswith("http") else []
    if cves:
        buttons.append(("🔎 NVD", nvd_link(cves[0])))
    if any(c in kev for c in cves):
        buttons.append(("🛡 CISA KEV", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"))
    return buttons


def render_card(group, kev, info, epss):
    """Compact card for a CVE that isn't known to be exploited."""
    first = group[0]
    cves = sorted({f["cve"] for f in group})
    scores = [info.get(c, {}).get("cvss") for c in cves]
    worst = max((x for x in scores if x is not None), default=None)
    sev = severity_of(worst)
    where = "VENDOR ADVISORY" if first["source_type"] == "vendor" else "NEW CVE"
    head = f"🆕 <b>{where}</b>" + (f" · {SEVERITY_ICON.get(sev, '')} <b>{sev.upper()}</b>" if sev else "")
    lines = [head, DIVIDER, f"<b>{esc(first['title'])}</b>", ""]
    for c in cves[:5]:
        lines.append(f"<code>{c}</code>")
        lines.append(f"📊 {esc(score_line(c, info.get(c, {}), epss, kev))}")
    if len(cves) > 5:
        lines.append(f"…and {len(cves) - 5} more CVEs")
    lines += ["", f"📰 {esc(first['source'])}", f"🕒 {found_time(first)}"]
    if first.get("summary"):
        short = first["summary"]
        short = short if len(short) <= 220 else short[:217].rsplit(" ", 1)[0] + "…"
        lines += ["", f"<i>{esc(short)}</i>"]
    return {"text": "\n".join(lines), "buttons": article_buttons(first["link"], cves, kev, first["source_type"])}


def render_detailed(group, top, kev, info, epss):
    """Full report for a CVE that is exploited or linked to malware."""
    first = group[0]
    cves = sorted({f["cve"] for f in group})
    confirmed = first["source_type"] in CONFIRMED_TYPES
    if top == KIND_RANK["malware"]:
        label = "🦠 <b>MALWARE LINKED TO CVE</b>"
    elif confirmed:
        label = "🛑 <b>VENDOR CONFIRMS EXPLOITATION</b>"
    else:
        label = "⚠️ <b>EXPLOITATION REPORTED</b>"
    scores = [info.get(c, {}).get("cvss") for c in cves]
    sev = severity_of(max((x for x in scores if x is not None), default=None))
    if sev:
        label += f" · {SEVERITY_ICON.get(sev, '')} <b>{sev.upper()}</b>"
    names = sorted({n for f in group for n in f["malware"]})
    terms = sorted({t for f in group for t in f["terms"]})

    lines = [label, DIVIDER, f"<b>{esc(first['title'])}</b>"]
    if first.get("summary"):
        lines += ["", "📝 <b>Summary</b>", f"<blockquote>{esc(first['summary'])}</blockquote>"]
    lines += ["", "🔢 <b>CVE details</b>"]
    for c in cves[:8]:
        lines.append(f"• <code>{c}</code>  {esc(score_line(c, info.get(c, {}), epss, kev))}")
        desc = info.get(c, {}).get("description")
        if desc and len(cves) <= 3:
            lines.append(f"   <i>{esc(desc if len(desc) <= 180 else desc[:177].rsplit(' ', 1)[0] + '…')}</i>")
    if len(cves) > 8:
        lines.append(f"…and {len(cves) - 8} more CVEs")
    lines.append("")
    if names:
        lines.append(f"🦠 <b>Malware:</b> {esc(', '.join(names))}")
    if terms:
        lines.append(f"🔍 <b>Keywords:</b> {esc(', '.join(terms[:8]))}")
    in_kev = [c for c in cves if c in kev]
    lines.append("🛡 <b>CISA KEV:</b> " + (", ".join(in_kev) + " listed" if in_kev else "not listed yet"))
    lines.append(f"📰 <b>Source:</b> {esc(first['source'])}")
    lines.append(f"🕒 <b>Found:</b> {found_time(first)}")
    return {"text": "\n".join(lines), "buttons": article_buttons(first["link"], cves, kev, first["source_type"])}


def render_kev(f, kev, info, epss):
    """Full report for a new CISA KEV entry."""
    cve = f["cve"]
    e = kev.get(cve, {})
    i = info.get(cve, {})
    sev = severity_of(i.get("cvss"), i.get("severity"))
    label = "🔴 <b>NEW IN CISA KEV · ACTIVELY EXPLOITED</b>"
    if sev:
        label += f" · {SEVERITY_ICON.get(sev, '')} <b>{sev.upper()}</b>"
    lines = [label, DIVIDER, f"<b>{esc(e.get('vulnerabilityName') or cve)}</b>"]
    if f.get("summary"):
        lines += ["", "📝 <b>Summary</b>", f"<blockquote>{esc(f['summary'])}</blockquote>"]
    lines += ["", "🔢 <b>CVE details</b>",
              f"• <code>{cve}</code>  {esc(score_line(cve, i, epss, kev))}",
              "",
              f"🏢 <b>Product:</b> {esc(e.get('vendorProject'))} {esc(e.get('product'))}",
              f"📅 <b>Added:</b> {esc(e.get('dateAdded'))} · <b>Federal due date:</b> {esc(e.get('dueDate'))}"]
    if f.get("ransomware"):
        lines.append("🟠 <b>Known ransomware use</b>")
    if e.get("requiredAction"):
        action = e["requiredAction"]
        lines.append(f"🛠 <b>Action:</b> {esc(action if len(action) <= 200 else action[:197] + '…')}")
    lines.append(f"🕒 <b>Found:</b> {found_time(f)}")
    buttons = [("🔎 NVD", nvd_link(cve)),
               ("🛡 CISA KEV", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog")]
    return {"text": "\n".join(lines), "buttons": buttons}


def render_malware_news(f):
    """Full report for a malware article that names no CVE."""
    lines = ["📰 <b>MALWARE NEWS</b>", DIVIDER, f"<b>{esc(f['title'])}</b>"]
    if f.get("summary"):
        lines += ["", "📝 <b>Summary</b>", f"<blockquote>{esc(f['summary'])}</blockquote>"]
    lines.append("")
    if f["malware"]:
        lines.append(f"🦠 <b>Malware:</b> {esc(', '.join(f['malware']))}")
    lines.append("🔢 <b>CVEs:</b> none named in the article")
    lines.append(f"📰 <b>Source:</b> {esc(f['source'])}")
    lines.append(f"🕒 <b>Found:</b> {found_time(f)}")
    buttons = [("📖 Read article", f["link"])] if f["link"].startswith("http") else []
    return {"text": "\n".join(lines), "buttons": buttons}


def build_digest(state, kev, since, api_key):
    """Group the last day's findings by CVE and write the digest messages."""
    recent = [f for f in state.get("findings", []) if (parse_time(f["time"]) or since) >= since]
    news_only = [f for f in recent if f["kind"] == "malware_news"]
    recent = [f for f in recent if f["kind"] != "malware_news"]
    if not recent and not news_only:
        return [f"📋 <b>Daily threat digest · {now_utc().astimezone(IST):%d %b %Y}</b>\n"
                "Nothing new in the last 24 hours across all sources."]

    by_cve = {}
    for f in recent:
        c = by_cve.setdefault(f["cve"], {"kinds": set(), "sources": {}, "malware": set(),
                                         "confirmed": False, "ransomware": False})
        c["kinds"].add(f["kind"])
        c["sources"].setdefault(f["source"], f["link"])
        c["malware"] |= set(f.get("malware", []))
        c["confirmed"] |= ((f["source_type"] in CONFIRMED_TYPES and f["kind"] in ("exploited", "malware"))
                           or f["kind"] == "kev")
        c["ransomware"] |= bool(f.get("ransomware"))

    for cve, c in by_cve.items():
        c["in_kev"] = cve in kev
        if c["in_kev"] and kev[cve].get("knownRansomwareCampaignUse", "").lower() == "known":
            c["ransomware"] = True

    epss = epss_lookup(sorted(by_cve)) if by_cve else {}

    def rank(item):
        cve, c = item
        return (c["in_kev"], c["confirmed"], len(c["sources"]), epss.get(cve, 0))

    ordered = sorted(by_cve.items(), key=rank, reverse=True)
    for cve, _ in ordered[:MAX_DIGEST_LOOKUPS]:
        by_cve[cve]["nvd"] = nvd_lookup(state, cve, api_key)

    def describe(cve, c):
        nvd = c.get("nvd") or {}
        k = kev.get(cve, {})
        product = f"{k.get('vendorProject', '')} {k.get('product', '')}".strip()
        bits = []
        if nvd.get("cvss") is not None:
            bits.append(f"CVSS {nvd['cvss']}")
        if cve in epss:
            bits.append(f"EPSS {epss[cve] * 100:.1f}%")
        bits.append("in KEV" if c["in_kev"] else "not in KEV")
        if c["confirmed"] and not c["in_kev"]:
            bits.append("vendor confirmed")
        if c["ransomware"]:
            bits.append("ransomware use")
        line = f"• {cve_link(cve)}"
        if product:
            line += f" · {esc(product)}"
        line += f"\n   {esc(' · '.join(bits))}"
        if c["malware"]:
            line += f"\n   🦠 {esc(', '.join(sorted(c['malware'])))}"
        sources = list(c["sources"].items())
        refs = ", ".join(f'<a href="{html.escape(u, quote=True)}">{esc(s)}</a>' for s, u in sources[:3])
        more = f" +{len(sources) - 3} more" if len(sources) > 3 else ""
        line += f"\n   {len(sources)} source{'s' if len(sources) != 1 else ''}: {refs}{more}"
        if not product and nvd.get("description"):
            d = nvd["description"]
            line += "\n   " + esc(d if len(d) <= 160 else d[:157].rsplit(" ", 1)[0] + "…")
        return line

    sections = [
        ("🔴 New in CISA KEV", [x for x in ordered if "kev" in x[1]["kinds"]]),
        ("🦠 Linked to malware", [x for x in ordered if "kev" not in x[1]["kinds"]
                                   and ("malware" in x[1]["kinds"] or x[1]["malware"])]),
        ("⚠️ Exploitation reported", [x for x in ordered if "exploited" in x[1]["kinds"]
                                      and not (x[1]["kinds"] & {"kev", "malware"})
                                      and not x[1]["malware"]]),
        ("🆕 Other new CVEs in the news", [x for x in ordered if x[1]["kinds"] == {"cve"}]),
    ]
    sources_count = len({f["source"] for f in recent + news_only})
    header = (f"📋 <b>Daily threat digest · {now_utc().astimezone(IST):%d %b %Y}</b>\n"
              f"{len(by_cve)} CVEs and {len(news_only)} malware stories from {sources_count} sources "
              "in the last 24 hours. Most urgent first.")
    pieces = [header]
    for title, items in sections:
        if items:
            pieces.append(f"\n<b>{title} ({len(items)})</b>")
            pieces += [describe(cve, c) for cve, c in items]
    if news_only:
        pieces.append(f"\n<b>📰 Malware news without a CVE ({len(news_only)})</b>")
        for f in news_only[:40]:
            extra = f" · 🦠 {esc(', '.join(f['malware']))}" if f["malware"] else ""
            pieces.append(f'• <a href="{html.escape(f["link"], quote=True)}">{esc(f["title"])}</a>'
                          f" · {esc(f['source'])}{extra}")

    # Pack into Telegram-sized messages (limit 4096 characters), never splitting an entry.
    messages, current = [], ""
    for piece in pieces:
        if current and len(current) + len(piece) + 1 > 3900:
            messages.append(current)
            current = ""
        current += ("\n" if current else "") + piece
    if current:
        messages.append(current)
    return messages


def digest_due(state):
    if os.environ.get("FORCE_DIGEST", "").strip().lower() in {"1", "true", "yes"}:
        return True
    now_ist = now_utc().astimezone(IST)
    hour, minute = (int(x) for x in DIGEST_TIME_IST.split(":"))
    if (now_ist.hour, now_ist.minute) < (hour, minute):
        return False
    return state.get("last_digest") != now_ist.date().isoformat()


# ---------------------------------------------------------------------------
# Telegram
# ---------------------------------------------------------------------------

def send_telegram(token, chat_id, text, buttons=None):
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    fields = {"chat_id": chat_id, "text": text[:4096], "parse_mode": "HTML",
              "disable_web_page_preview": "true"}
    if buttons:  # one row of tap-able link buttons under the message
        fields["reply_markup"] = json.dumps(
            {"inline_keyboard": [[{"text": label, "url": u} for label, u in buttons]]})
    payload = urllib.parse.urlencode(fields).encode()
    for _ in range(3):
        try:
            urllib.request.urlopen(urllib.request.Request(url, data=payload), timeout=30)
            return True
        except urllib.error.HTTPError as err:
            body = err.read().decode(errors="replace")
            if err.code == 429:  # Telegram says "slow down"
                wait = json.loads(body).get("parameters", {}).get("retry_after", 5)
                time.sleep(wait + 1)
                continue
            if err.code == 400 and fields.get("parse_mode"):
                # Telegram couldn't read the formatting: resend as plain text so the alert isn't lost
                log(f"Telegram rejected the formatting ({body[:120]}), resending as plain text")
                fields.pop("parse_mode")
                fields["text"] = html.unescape(re.sub(r"<[^>]+>", "", fields["text"]))
                payload = urllib.parse.urlencode(fields).encode()
                continue
            log(f"Telegram error {err.code}: {body}")
            return False
        except urllib.error.URLError as err:
            log(f"Telegram connection error: {err}")
            time.sleep(3)
    return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    nvd_key = os.environ.get("NVD_API_KEY", "").strip()
    dry_run = not (token and chat_id)
    if dry_run:
        log("DRY-RUN: Telegram settings not found, messages will be printed only")

    config = json.loads(SOURCES_FILE.read_text(encoding="utf-8"))
    state = load_state()
    brand_new = not state
    state.setdefault("findings", [])
    run_id = now_utc().isoformat()
    if "last_digest" not in state:  # first digest comes at the next scheduled time, not now
        state["last_digest"] = now_utc().astimezone(IST).date().isoformat()
        state["last_digest_time"] = now_utc().isoformat(timespec="seconds")

    kev = {}
    try:
        kev = check_kev(state, config["kev_url"], run_id)
    except Exception as err:  # one broken source shouldn't stop the others
        log(f"KEV check failed: {err}")
    reached = check_feeds(state, config["feeds"], run_id)
    check_bluesky(state, config, run_id)
    check_x(state, config, run_id)

    messages = instant_alerts(state, kev, run_id, nvd_key)
    if len(messages) > MAX_INSTANT_ALERTS_PER_RUN:
        extra = len(messages) - MAX_INSTANT_ALERTS_PER_RUN
        messages = messages[:MAX_INSTANT_ALERTS_PER_RUN]
        messages.append(f"…and {extra} more new items this run. They'll all be in the daily digest.")

    if brand_new:
        messages = [
            "✅ <b>Threat Intel Monitor is running.</b>\n"
            f"Watching the CISA KEV catalog ({len(state.get('kev', []))} entries) and "
            f"{reached} of {len(config['feeds'])} feeds. Instant alerts arrive as things happen; "
            f"a daily digest comes at {DIGEST_TIME_IST} IST."
        ]
    elif digest_due(state):
        since = parse_time(state.get("last_digest_time")) or (now_utc() - timedelta(days=1))
        since = max(since, now_utc() - timedelta(days=1, hours=2))
        messages += build_digest(state, kev, since, nvd_key)
        state["last_digest"] = now_utc().astimezone(IST).date().isoformat()
        state["last_digest_time"] = now_utc().isoformat(timespec="seconds")

    sent = 0
    for message in messages:
        text, buttons = (message["text"], message.get("buttons")) if isinstance(message, dict) else (message, None)
        if dry_run:
            print("\n" + "-" * 60 + "\n" + text)
            if buttons:
                print("   " + "  ".join(f"[ {label} ]" for label, _ in buttons))
        elif send_telegram(token, chat_id, text, buttons):
            sent += 1
            time.sleep(1)

    save_state(state)
    log(f"Done. {reached}/{len(config['feeds'])} feeds read, {len(messages)} messages, {sent} sent.")


if __name__ == "__main__":
    sys.exit(main())
