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
      🧬 a malware article, even if it names no CVE
      💥 a public exploit, PoC, Metasploit module or Nuclei template for a CVE
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
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Settings you might want to change
# ---------------------------------------------------------------------------

DIGEST_TIME_IST = "09:00"        # when the daily digest is sent (India time)
MAX_INSTANT_ALERTS_PER_RUN = 30  # stops a flood of messages on a busy day
MAX_DIGEST_LOOKUPS = 40          # most CVEs to look up in NVD per digest
FINDINGS_KEPT_DAYS = 7           # how long findings are kept for the digest
THREAD_DAYS = 14                 # a CVE's alert message is edited (not re-sent) for this long
BLOCK_LINES = 6                  # most CVEs listed per vendor block in the digest (the rest are counted)
ALERT_REPEAT_DAYS = 14           # don't re-alert the same CVE for the same reason
NEARBY_SENTENCES = 2             # how far from a CVE mention to look for malware words
FEED_TIMEOUT = 15                # seconds to wait on one feed before giving up on it
FEED_WORKERS = 10                # feeds downloaded at the same time
LINK_MEMORY_DAYS = 45            # how long article links are remembered (stops old stories coming back)
NVD_BUDGET_ALERTS = 90           # seconds allowed for NVD lookups before instant alerts go out
NVD_BUDGET_DIGEST = 120          # seconds allowed for NVD lookups for the digest
OUTBOX_MAX_HOURS = 12            # undelivered messages are retried for this long
SOCIAL_CUTOFF_MINUTES = 7        # skip optional sources if a run is already this slow
BACKUP_EVERY_HOURS = 20          # how often seen.json is backed up to the repo

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
# Watchlist, vendors and grouping (settings come from sources.json via configure())
# ---------------------------------------------------------------------------

SETTINGS = {
    "watch": [],         # [(term, regex)] products you care most about
    "vendors": [],       # [(vendor name, regex of its name and products)]
    "mute_other": False, # plain new-CVE cards arrive without a notification sound
    "min_group": 3,      # this many plain new-CVE alerts for one vendor become one message (0 = off)
    "malware_news": True,  # alert on (and digest) malware articles that name no CVE
    "new_cve_instant": "watchlist_critical",  # plain new CVEs: "all" | "watchlist_critical" | "none"
    "critical_cvss": 9.0,  # what counts as critical for "watchlist_critical"
}


def _term_regex(terms):
    """Case-insensitive match of any term as a whole word (so 'AMD' doesn't match 'SAMDS')."""
    alt = "|".join(re.escape(t) for t in sorted(terms, key=len, reverse=True))
    return re.compile(r"(?<![A-Za-z0-9])(?:" + alt + r")(?![A-Za-z0-9])", re.IGNORECASE)


def configure(config):
    """Read the watchlist, vendor list and grouping settings from sources.json."""
    terms = list(config.get("watchlist", {}).get("terms", []))
    terms += [t.strip() for t in os.environ.get("WATCHLIST", "").split(",") if t.strip()]
    SETTINGS["watch"] = [(t, _term_regex([t])) for t in dict.fromkeys(terms)]
    SETTINGS["vendors"] = [
        (name, _term_regex([name] + list(products)))
        for name, products in config.get("vendors", {}).items()
        if not name.startswith("_") and isinstance(products, list)]
    SETTINGS["mute_other"] = bool(config.get("watchlist", {}).get("mute_other_new_cves", False))
    SETTINGS["min_group"] = int(config.get("grouping", {}).get("min_alerts_per_vendor", 3) or 0)
    SETTINGS["malware_news"] = bool(config.get("malware_news", {}).get("alerts", True))
    alerts = config.get("alerts", {})
    SETTINGS["new_cve_instant"] = alerts.get("new_cve_instant", "watchlist_critical")
    SETTINGS["critical_cvss"] = float(alerts.get("critical_cvss", 9.0))


def watch_hits(text):
    """Watchlist terms mentioned in the text."""
    return [term for term, rx in SETTINGS["watch"] if rx.search(text or "")]


def detect_vendor(*texts):
    """Vendor named in the first text that names one. Within a text, the earliest mention wins."""
    for text in texts:
        best = None
        for name, rx in SETTINGS["vendors"]:
            m = rx.search(text or "")
            if m and (best is None or m.start() < best[0]):
                best = (m.start(), name)
        if best:
            return best[1]
    return ""


def watch_label(hits, vendor=""):
    """Short watchlist label: one entry per vendor, never every product of the same vendor."""
    names = []
    for term in hits:
        name = detect_vendor(term) or term
        if name not in names:
            names.append(name)
    if vendor and vendor in names:  # the CVE's own vendor first
        names.remove(vendor)
        names.insert(0, vendor)
    return ", ".join(names[:2]) + (f" +{len(names) - 2}" if len(names) > 2 else "")


def vendor_and_watch(group, info, kev):
    """(vendor, watchlist hits) for findings that are about the same CVE(s)."""
    cves = {f["cve"] for f in group if f.get("cve")}
    kev_text = " ".join(f"{kev[c].get('vendorProject', '')} {kev[c].get('product', '')} "
                        f"{kev[c].get('vulnerabilityName', '')}" for c in cves if c in kev)
    titles = " ".join(f.get("title", "") for f in group)
    descs = " ".join(info.get(c, {}).get("description", "") for c in cves)
    summaries = " ".join(f.get("summary", "") for f in group)
    vendor = detect_vendor(kev_text, titles, descs, summaries)
    return vendor, watch_hits(f"{kev_text} {titles} {descs} {summaries}")


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


def link_memory(state):
    """Article links seen so far, as {link: date first seen}. Older saves kept a plain list."""
    mem = state.get("articles")
    if isinstance(mem, list):
        today = now_utc().date().isoformat()
        mem = {link: today for link in mem}
    elif not isinstance(mem, dict):
        mem = {}
    state["articles"] = mem
    return mem


def save_state(state):
    cutoff_findings = now_utc() - timedelta(days=FINDINGS_KEPT_DAYS)
    cutoff_alerts = now_utc() - timedelta(days=ALERT_REPEAT_DAYS)
    oldest = (now_utc() - timedelta(days=LINK_MEMORY_DAYS)).date().isoformat()
    links = {k: v for k, v in link_memory(state).items() if v >= oldest}
    if len(links) > 60000:  # safety cap; keeps the newest
        links = dict(sorted(links.items(), key=lambda kv: kv[1])[-60000:])
    state["articles"] = links
    state["findings"] = [f for f in state.get("findings", [])
                         if (parse_time(f.get("time")) or now_utc()) > cutoff_findings]
    state["alerted"] = {k: v for k, v in state.get("alerted", {}).items()
                        if (parse_time(v) or now_utc()) > cutoff_alerts}
    cutoff_threads = now_utc() - timedelta(days=THREAD_DAYS)
    state["threads"] = {c: t for c, t in state.get("threads", {}).items()
                        if (parse_time(t.get("time")) or now_utc()) > cutoff_threads}
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


# Words in an article -> the malware type shown on the threat profile card
MALWARE_TYPES = {
    "ransomware": ["ransomware"],
    "infostealer": ["infostealer", "info-stealer", "stealer", "credential stealer"],
    "botnet": ["botnet"],
    "RAT": ["remote access trojan", "rat"],
    "backdoor": ["backdoor", "backdoors"],
    "loader": ["loader", "dropper", "downloader"],
    "trojan": ["trojan", "banking trojan"],
    "cryptominer": ["cryptominer", "crypto miner", "coinminer", "cryptojacking", "xmrig"],
    "web shell": ["webshell", "web shell", "webshells", "web shells"],
    "rootkit / bootkit": ["rootkit", "bootkit"],
    "spyware": ["spyware", "stalkerware"],
    "wiper": ["wiper"],
    "worm": ["worm", "self-propagating"],
}
# Words in an article -> how the malware is spread
DELIVERY_METHODS = {
    "phishing": ["phishing", "spear-phishing", "spearphishing", "phishing emails", "malicious emails",
                 "email attachments", "smishing", "vishing"],
    "ClickFix / fake CAPTCHA": ["clickfix", "fake captcha", "filefix"],
    "malvertising": ["malvertising", "malicious ads", "malicious advertisements", "sponsored ads"],
    "SEO poisoning": ["seo poisoning", "search engine poisoning"],
    "supply chain": ["supply chain", "supply-chain"],
    "malicious packages": ["npm", "pypi", "malicious packages", "nuget", "rubygems", "crates.io"],
    "fake / trojanized software": ["fake installer", "fake installers", "trojanized", "cracked software",
                                   "pirated software", "fake updates", "fake update", "fake browser update"],
    "malicious extensions": ["browser extension", "browser extensions", "malicious extension",
                             "malicious extensions", "vs code extension", "vscode extension"],
    "compromised websites": ["compromised websites", "compromised sites", "watering hole", "drive-by"],
    "exploited vulnerabilities": ["exploiting vulnerabilities", "exploits known vulnerabilities",
                                  "exploiting known flaws", "n-day"],
    "USB / removable media": ["usb drive", "usb drives", "removable media"],
}


def labels_found(text, table):
    """Which labels from a word table appear in the text (in the table's order)."""
    found = []
    for label, words in table.items():
        if phrase_regex(words).search(text):
            found.append(label)
    return found


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
        kind = "poc" if source_type == "exploit" else classify(r)
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
    if not results and source_type not in ("social", "exploit") and title_is_malware_news(title):
        opening = title + ". " + strip_html(body)[:2500]
        _, _, names = sentence_signals(opening)
        state["findings"].append({
            "cve": None, "kind": "malware_news", "source": source, "source_type": source_type,
            "title": title, "link": link, "malware": sorted(names), "terms": [],
            "mtypes": labels_found(opening, MALWARE_TYPES),
            "delivery": labels_found(opening, DELIVERY_METHODS),
            "summary": summary,
            "time": now_utc().isoformat(timespec="seconds"), "run": run_id,
        })
        added += 1
    return added


def _download_feed(feed):
    """Fetch and parse one feed. Never raises: returns (feed, items or None, error or None)."""
    try:
        return feed, parse_feed(fetch(feed["url"], timeout=FEED_TIMEOUT)), None
    except Exception as err:  # any failure (timeouts, dropped connections, bad XML) skips just this feed
        return feed, None, err


def check_feeds(state, feeds, run_id):
    seen = link_memory(state)
    today = now_utc().date().isoformat()
    feeds_read = set(state.get("feeds_read", []))
    reached = 0

    # Download all feeds at once (a slow site no longer holds up the others), then process in order.
    with ThreadPoolExecutor(max_workers=FEED_WORKERS) as pool:
        results = list(pool.map(_download_feed, feeds))

    for feed, items, err in results:
        name, kind = feed["name"], feed.get("type", "news")
        if err is not None:
            log(f"Could not read {name}: {type(err).__name__}: {err}")
            continue
        reached += 1
        first_read = name not in feeds_read
        feeds_read.add(name)
        new_matches = 0
        try:
            for title, link, body in items:
                if not link or link in seen:
                    continue
                seen[link] = today
                if first_read:
                    continue  # remember the backlog, don't report it
                new_matches += record_item(state, name, kind, title, link, body, run_id)
        except Exception as err:  # a strange item shouldn't stop the other feeds
            log(f"Error while processing {name}: {type(err).__name__}: {err}")
        note = " (first read: saved without alerts)" if first_read else ""
        log(f"{name}: {len(items)} items, {new_matches} new CVE matches{note}")

    state["feeds_read"] = sorted(feeds_read)
    return reached


# ---------------------------------------------------------------------------
# Optional social sources: Bluesky (free login) and X/Twitter (paid API)
# ---------------------------------------------------------------------------

def remember_post(state, link, source):
    """True if this post is new. The first time a source is read, only remember."""
    seen = link_memory(state)
    if link in seen:
        return False
    seen[link] = now_utc().date().isoformat()
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
# GitHub: PoC repositories, Metasploit modules, Nuclei templates, advisory database
# (uses the token GitHub Actions provides automatically, through GitHub's official API)
# ---------------------------------------------------------------------------

def github_api(path, token):
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return json.loads(fetch("https://api.github.com" + path, headers=headers))


def check_github(state, config, run_id):
    settings = config.get("github", {})
    if not settings:
        return 0
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    added = 0

    def seen_first(source):
        if source not in state["feeds_read"]:
            state["feeds_read"].append(source)
            log(f"{source}: first read, saved items without alerts")

    # 1) Newly created repositories named after a CVE: usually PoCs (sometimes fake ones)
    since = (now_utc() - timedelta(days=2)).date().isoformat()
    for query in settings.get("poc_queries", []):
        q = urllib.parse.quote(f"{query} created:>={since}")
        try:
            repos = github_api(f"/search/repositories?q={q}&sort=updated&order=desc&per_page=50",
                               token).get("items", [])
        except Exception as err:
            log(f"GitHub PoC search '{query}' failed: {err}")
            continue
        for r in repos:
            text = f"{r.get('full_name', '')} {r.get('description') or ''}"
            if len({c.upper() for c in CVE_PATTERN.findall(text)}) > 3:
                continue  # big collections of many CVEs, not a specific PoC
            if remember_post(state, r["html_url"], "GitHub PoC"):
                added += record_item(state, "GitHub PoC repository", "exploit",
                                     f"{r['full_name']}: {r.get('description') or 'no description'}",
                                     r["html_url"], r.get("description") or "", run_id)
    seen_first("GitHub PoC")

    # 2) Recent commits to exploit/detection projects that name a CVE
    for item in settings.get("commit_repos", []):
        try:
            commits = github_api(f"/repos/{item['repo']}/commits?per_page=50", token)
        except Exception as err:
            log(f"GitHub {item['name']} commits failed: {err}")
            continue
        for c in commits:
            message = (c.get("commit", {}).get("message") or "").strip()
            if not CVE_PATTERN.search(message):
                continue
            headline = message.splitlines()[0][:200]
            if remember_post(state, c["html_url"], item["name"]):
                added += record_item(state, item["name"], "exploit", headline,
                                     c["html_url"], message[:1500], run_id)
        seen_first(item["name"])

    # 3) GitHub's reviewed advisory database (open-source packages)
    for severity in settings.get("advisory_severities", []):
        try:
            advisories = github_api(f"/advisories?type=reviewed&severity={severity}"
                                    "&sort=published&direction=desc&per_page=50", token)
        except Exception as err:
            log(f"GitHub advisories ({severity}) failed: {err}")
            continue
        for a in advisories:
            if not a.get("cve_id"):
                continue
            body = f"{(a.get('description') or a.get('summary', ''))[:1500]}\n\nCVE: {a['cve_id']}"
            if remember_post(state, a["html_url"], "GitHub Advisory Database"):
                added += record_item(state, "GitHub Advisory Database", "vendor",
                                     a.get("summary", a["cve_id"]), a["html_url"], body, run_id)
    if settings.get("advisory_severities"):
        seen_first("GitHub Advisory Database")
    log(f"GitHub: {added} new CVE matches")
    return added


# ---------------------------------------------------------------------------
# Dashboard data: a small public feed.json the portfolio page reads
# ---------------------------------------------------------------------------

def write_dashboard(state, kev, sources_watched):
    """Last 7 days of findings plus summary numbers, written to feed.json."""
    week_ago = now_utc() - timedelta(days=7)
    recent = [f for f in state.get("findings", []) if (parse_time(f.get("time")) or week_ago) >= week_ago]
    recent.sort(key=lambda f: f.get("time", ""), reverse=True)

    items, seen = [], set()
    for f in recent:
        key = (f.get("cve") or f["link"], f["kind"])
        if key in seen:
            continue
        seen.add(key)
        items.append({
            "time": f.get("time"), "kind": f["kind"], "cve": f.get("cve"),
            "title": f.get("title", "")[:200], "link": f.get("link"), "source": f.get("source"),
            "source_type": f.get("source_type"), "malware": f.get("malware", [])[:5],
            "cvss": f.get("cvss"), "epss": f.get("epss"),
            "in_kev": bool(f.get("cve") and f["cve"] in kev),
            "mtypes": f.get("mtypes", []),
        })

    by_day = {}
    for f in recent:
        day = (parse_time(f["time"]) or now_utc()).astimezone(IST).date().isoformat()
        by_day[day] = by_day.get(day, 0) + 1
    days = [(now_utc().astimezone(IST).date() - timedelta(days=d)).isoformat() for d in range(6, -1, -1)]

    def top(counter, n=6):
        return [{"name": k, "count": v} for k, v in sorted(counter.items(), key=lambda x: -x[1])[:n]]

    malware, sources = {}, {}
    for f in recent:
        for name in f.get("malware", []):
            malware[name] = malware.get(name, 0) + 1
        sources[f["source"]] = sources.get(f["source"], 0) + 1

    def unique_cves(kind):
        return len({f["cve"] for f in recent if f["kind"] == kind and f.get("cve")})

    feed = {
        "generated": now_utc().isoformat(timespec="seconds"),
        "sources_watched": sources_watched,
        "totals": {
            "new_cves": len({f["cve"] for f in recent if f.get("cve")}),
            "exploited": unique_cves("exploited"),
            "malware_linked": unique_cves("malware"),
            "public_exploits": unique_cves("poc"),
            "kev_added": unique_cves("kev"),
            "malware_stories": len({f["link"] for f in recent if f["kind"] == "malware_news"}),
        },
        "per_day": [{"day": d, "count": by_day.get(d, 0)} for d in days],
        "top_malware": top(malware),
        "top_sources": top(sources),
        "items": items[:150],
    }
    (HERE / "feed.json").write_text(json.dumps(feed, ensure_ascii=False, indent=1), encoding="utf-8")


# ---------------------------------------------------------------------------
# Enrichment: NVD (CVSS, product) and FIRST EPSS
# ---------------------------------------------------------------------------

NVD_LIMIT = {"until": 0.0, "fails": 0, "noted": False}


def nvd_budget(seconds):
    """Allow NVD lookups for this many seconds from now. After that, messages go out without CVSS."""
    NVD_LIMIT.update(until=time.monotonic() + seconds, fails=0, noted=False)


def nvd_lookup(state, cve, api_key):
    cache = state.setdefault("nvd_cache", {})
    cached = cache.get(cve)
    if cached and (now_utc() - (parse_time(cached.get("time")) or now_utc())).days < 3:
        return cached
    if time.monotonic() > NVD_LIMIT["until"] or NVD_LIMIT["fails"] >= 3:
        if not NVD_LIMIT["noted"]:
            NVD_LIMIT["noted"] = True
            why = "NVD is not responding" if NVD_LIMIT["fails"] >= 3 else "NVD time budget used up"
            log(f"{why}: sending the remaining alerts without CVSS")
        return cached or {}
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + urllib.parse.quote(cve)
    headers = {"apiKey": api_key} if api_key else {}
    info = {"time": now_utc().isoformat(timespec="seconds")}
    try:
        data = json.loads(fetch(url, timeout=12, headers=headers))
        NVD_LIMIT["fails"] = 0
        vulns = data.get("vulnerabilities", [])
        info["found"] = bool(vulns)  # False = NVD has no record of this CVE yet
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
    except Exception as err:  # NVD is often slow; never let it break the alerts
        NVD_LIMIT["fails"] += 1
        log(f"NVD lookup failed for {cve}: {err}")
        return cached or {}
    cache.pop(cve, None)  # re-insert so recently used entries are the last to be trimmed
    cache[cve] = info
    if time.monotonic() < NVD_LIMIT["until"]:
        time.sleep(0.7 if api_key else 6.5)  # NVD allows 5 requests per 30 s without a key
    return info


def epss_lookup(cves):
    scores = {}
    for i in range(0, len(cves), 50):
        batch = cves[i:i + 50]
        try:
            data = json.loads(fetch("https://api.first.org/data/v1/epss?cve=" + ",".join(batch), timeout=15))
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
    elif info.get("found") is False:
        bits.append("🆕 not in NVD yet")
    else:
        bits.append("CVSS not published yet")
    bits.append(f"EPSS {epss[cve] * 100:.1f}%" if cve in epss else "EPSS n/a")
    bits.append("in KEV ✅" if cve in kev else "not in KEV")
    return " · ".join(bits)


def instant_alerts(state, kev, run_id, api_key=""):
    """Turn this run's new findings into Telegram messages (dicts with text and buttons)."""
    alerted = state.setdefault("alerted", {})
    fresh = [f for f in state["findings"] if f.get("run") == run_id]
    # Messages still waiting in the outbox count as alerted, so they aren't planned twice.
    known = dict(alerted)
    for m in state.get("outbox", []):
        for key, when in m.get("keys", []):
            known.setdefault(key, when)

    # --- 1) decide what to alert on -------------------------------------------------
    # A CVE is alerted again only when its news gets more serious:
    # plain CVE -> exploited -> malware -> KEV. Ten copies of one story send one alert.
    best = {}
    for key in known:
        cve, _, kind = key.partition("|")
        best[cve] = max(best.get(cve, -1), KIND_RANK.get(kind, 0))
    planned = []  # (kind of message, [findings], [(alerted key, time)] to record once delivered)
    for f in (x for x in fresh if x["kind"] == "kev"):
        known[f"{f['cve']}|kev"] = f["time"]
        best[f["cve"]] = KIND_RANK["kev"]
        planned.append(("kev", [f], [(f"{f['cve']}|kev", f["time"])]))
    poc_by_link = {}
    for f in (x for x in fresh if x["kind"] == "poc"):
        key = f"{f['cve']}|poc"
        if key in known:
            continue  # one exploit alert per CVE
        known[key] = f["time"]
        best[f["cve"]] = max(best.get(f["cve"], -1), 0)  # no separate "new CVE" card later
        poc_by_link.setdefault(f["link"], []).append(f)
    planned += [("poc", group, [(f"{f['cve']}|poc", f["time"]) for f in group]) for group in poc_by_link.values()]
    by_article = {}
    for f in (x for x in fresh if x["kind"] not in ("kev", "poc")):
        by_article.setdefault(f["link"], []).append(f)
    for link, group in by_article.items():
        if group[0]["kind"] == "malware_news":
            if SETTINGS["malware_news"]:  # switched off in sources.json -> CVE alerts only
                planned.append(("malware_news", group[:1], []))
            continue
        new, keys = [], []
        for f in group:
            rank = KIND_RANK[f["kind"]]
            if rank > best.get(f["cve"], -1):
                new.append(f)
                best[f["cve"]] = rank
                keys.append((f"{f['cve']}|{f['kind']}", f["time"]))
        if new:
            planned.append(("article", new, keys))

    # --- 2) plain new CVEs: instant only if configured, otherwise they wait for the digest ---
    def is_plain(kind, group):
        return kind == "article" and max(KIND_RANK[f["kind"]] for f in group) == KIND_RANK["cve"]

    mode = SETTINGS["new_cve_instant"]
    kept = []
    for item in planned:
        kind, group, keys = item
        if is_plain(kind, group) and mode != "all":
            if mode == "none" or not vendor_and_watch(group, {}, kev)[1]:
                continue  # not recorded as alerted: it simply appears in the daily digest
        kept.append(item)
    planned = kept

    # --- 3) look up CVSS and EPSS for the CVEs we're about to report (urgent ones first) ---
    urgent = sorted({f["cve"] for kind, group, _ in planned if not is_plain(kind, group)
                     for f in group if f.get("cve")})
    plain = sorted({f["cve"] for kind, group, _ in planned if is_plain(kind, group)
                    for f in group} - set(urgent))
    cves = urgent + plain
    epss = epss_lookup(cves) if cves else {}
    info = {}
    for cve in cves[:MAX_ALERT_LOOKUPS]:
        info[cve] = nvd_lookup(state, cve, api_key)
    if mode == "watchlist_critical":  # a watchlist hit alone is not enough: it must also be critical
        crit = SETTINGS["critical_cvss"]
        planned = [(kind, group, keys) for kind, group, keys in planned
                   if not is_plain(kind, group)
                   or any((info.get(f["cve"], {}).get("cvss") or 0) >= crit for f in group)]
    for _, group, _ in planned:  # keep the scores with the findings (used by the dashboard)
        for f in group:
            if f.get("cve"):
                f["cvss"] = info.get(f["cve"], {}).get("cvss")
                f["epss"] = epss.get(f["cve"])

    # --- 4) tag watchlist hits and vendors; merge plain new-CVE cards from one vendor ---
    entries = []
    for kind, group, keys in planned:
        vendor, hits = ("", []) if kind == "malware_news" else vendor_and_watch(group, info, kev)
        entries.append({"kind": kind, "group": group, "keys": keys, "vendor": vendor,
                        "watch": hits, "plain": is_plain(kind, group)})
    min_group = SETTINGS["min_group"]
    if min_group and mode == "all":
        by_vendor = {}
        for e in entries:
            if e["plain"] and e["vendor"]:
                by_vendor.setdefault(e["vendor"], []).append(e)
        for vendor, members in by_vendor.items():
            if len({f["cve"] for e in members for f in e["group"]}) >= min_group:
                ids = {id(e) for e in members}
                first = next(i for i, e in enumerate(entries) if id(e) in ids)
                merged = {"kind": "group", "vendor": vendor, "plain": True,
                          "watch": sorted({h for e in members for h in e["watch"]}),
                          "group": [f for e in members for f in e["group"]],
                          "keys": [k for e in members for k in e["keys"]]}
                entries = [e for e in entries if id(e) not in ids]
                entries.insert(first, merged)

    # --- 5) one message per CVE: send it once, then edit it as the story escalates ---
    threads = state.setdefault("threads", {})
    now = now_utc()
    singles = {}
    for e in entries:
        ids = {f["cve"] for f in e["group"] if f.get("cve")}
        if e["kind"] in ("kev", "poc", "article") and len(ids) == 1:
            e["cve"] = next(iter(ids))
            e["type"] = entry_type(e["kind"], e["group"])
            singles.setdefault(e["cve"], []).append(e)
    dropped = set()
    for cve, group_entries in singles.items():  # several findings about one CVE in one run
        group_entries.sort(key=lambda x: TYPE_RANK[x["type"]])
        top = group_entries[-1]
        top["keys"] = [k for x in group_entries for k in x["keys"]]
        top["events"] = [make_event(x["type"], x["group"]) for x in group_entries]
        dropped |= {id(x) for x in group_entries[:-1]}
    entries = [e for e in entries if id(e) not in dropped]

    messages = []
    for e in entries:
        kind, group, keys = e["kind"], e["group"], e["keys"]
        names = source_names(state, {f["cve"] for f in group if f.get("cve")})
        if e.get("cve"):
            cve, typ = e["cve"], e["type"]
            th = threads.get(cve)
            live = bool(th and th.get("message_id")
                        and now - (parse_time(th.get("time")) or now) < timedelta(days=THREAD_DAYS))
            events = (th["events"] if live else []) + (e.get("events") or [make_event(typ, group)])
            msg = compact_card(typ, group, kev, info, epss, names, e["watch"], e["vendor"], events)
            if live and typ != "kev":
                msg["edit"] = th["message_id"]  # quiet update of this CVE's earlier message
            msg["thread"] = {"cve": cve, "events": events}  # a KEV entry always gets a fresh message
        elif kind == "malware_news":
            msg = render_malware_news(group[0])
        elif kind == "group":
            msg = render_group(e["vendor"], group, kev, info, epss, e["watch"])
        else:
            msg = compact_card(entry_type(kind, group), group, kev, info, epss, names, e["watch"], e["vendor"])
        msg = dict(msg) if isinstance(msg, dict) else {"text": msg}
        if e["plain"] and SETTINGS["mute_other"] and not e["watch"]:
            msg["silent"] = True  # plain new CVE outside your watchlist: no notification sound
        msg["keys"] = [list(k) for k in keys]
        messages.append(msg)
    return messages


def article_buttons(link, cves, kev, source_type="news"):
    label = {"social": "💬 Open post", "vendor": "📖 Read advisory",
             "government": "📖 Read advisory"}.get(source_type, "📖 Read article")
    buttons = [(label, link)] if link.startswith("http") else []
    if cves:
        buttons.append(("🔎 NVD", nvd_link(cves[0])))
    if any(c in kev for c in cves):
        buttons.append(("🛡 CISA KEV", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"))
    return buttons


TYPE_ICON = {"kev": "🔴", "malware": "🦠", "confirmed": "🛑", "exploited": "⚠️", "poc": "💥", "cve": "🆕"}
TYPE_RANK = {"cve": 0, "exploited": 1, "confirmed": 1, "poc": 1, "malware": 2, "kev": 3}
TYPE_EVENT = {"kev": "added to CISA KEV", "malware": "linked to malware", "confirmed": "exploitation confirmed",
              "exploited": "exploitation reported", "poc": "public exploit", "cve": "new CVE"}


def entry_type(kind, group):
    """What kind of alert this is: kev, malware, confirmed / exploited, poc or a plain new cve."""
    if kind in ("kev", "poc"):
        return kind
    top = max(KIND_RANK[f["kind"]] for f in group)
    if top == KIND_RANK["malware"]:
        return "malware"
    if top == KIND_RANK["exploited"]:
        return "confirmed" if group[0]["source_type"] in CONFIRMED_TYPES else "exploited"
    return "cve"


def make_event(typ, group):
    """One line of a CVE's timeline."""
    names = sorted({n for f in group for n in f["malware"]})
    label = TYPE_EVENT[typ] + (": " + ", ".join(names[:3]) if typ == "malware" and names else "")
    return {"t": group[0]["time"], "icon": TYPE_ICON[typ], "label": label, "source": group[0]["source"]}


def source_names(state, cves):
    """Every source that has reported these CVEs (newest findings are kept for a week)."""
    names = []
    for f in state.get("findings", []):
        if f.get("cve") in cves and f["source"] not in names:
            names.append(f["source"])
    return names


def one_sentence(text, limit=150):
    parts = sentences((text or "").strip())
    first = parts[0] if parts else ""
    return first if len(first) <= limit else first[:limit - 1].rsplit(" ", 1)[0] + "…"


def facts_for(cve, info, epss):
    bits, i = [], info.get(cve, {})
    if i.get("cvss") is not None:
        bits.append(f"CVSS {i['cvss']} ({severity_of(i['cvss'], i.get('severity'))})")
    elif i.get("found") is False:
        bits.append("🆕 not in NVD yet")
    if cve in epss:
        bits.append(f"EPSS {epss[cve] * 100:.0f}%")
    return bits


def compact_card(typ, group, kev, info, epss, sources, hits=(), vendor="", events=None):
    """Four lines: what and which product / key facts / one-sentence summary / sources.
    When the CVE has a history, a short timeline is added underneath."""
    first = group[0]
    cves = sorted({f["cve"] for f in group})
    k = kev.get(cves[0], {})
    product = f"{k.get('vendorProject', '')} {k.get('product', '')}".strip() or vendor
    head = ("👀 " if hits else "") + f"{TYPE_ICON[typ]} <b>{cves[0]}</b>"
    head += f" +{len(cves) - 1}" if len(cves) > 1 else ""
    head += f" · {esc(product)}" if product else ""
    names = sorted({n for f in group for n in f["malware"]})
    if typ == "kev":
        what = ["KEV"]
        if first.get("ransomware") or k.get("knownRansomwareCampaignUse", "").lower() == "known":
            what.append("ransomware use")
        if k.get("dueDate"):
            what.append(f"due {k['dueDate']}")
    elif typ == "malware":
        what = ["Malware: " + ", ".join(names[:3])] if names else ["malware linked"]
    elif typ == "confirmed":
        what = ["government advisory: exploited" if first["source_type"] == "government"
                else "vendor confirms exploitation"]
    elif typ == "exploited":
        what = ["exploitation reported"]
    elif typ == "poc":
        what = ["public exploit"]
    else:
        what = ["vendor advisory" if first["source_type"] == "vendor" else "new CVE"]
    if len(cves) == 1:
        what += facts_for(cves[0], info, epss)
        if typ != "kev" and cves[0] in kev:
            what.append("in KEV ✅")
    else:
        scores = [info.get(c, {}).get("cvss") for c in cves if info.get(c, {}).get("cvss") is not None]
        if scores:
            what.append(f"CVSS up to {max(scores)}")
    lines = [head, esc(" · ".join(what))]
    if len(cves) > 1:
        lines.append(esc("also " + ", ".join(cves[1:4]) + (f" +{len(cves) - 4} more" if len(cves) > 4 else "")))
    summary = one_sentence((k.get("vulnerabilityName") if typ == "kev" else "")
                           or first.get("summary") or first.get("title") or k.get("vulnerabilityName", ""))
    if summary:
        lines.append(f"<i>{esc(summary)}</i>")
    if events and len(events) > 1:
        for ev in events[-6:]:
            when = (parse_time(ev["t"]) or now_utc()).astimezone(IST).strftime("%d %b %H:%M")
            lines.append(f"↳ {when} {ev['icon']} {esc(ev['label'])} · {esc(ev['source'])}")
    names_seen = sources or [first["source"]]
    if typ == "kev":  # lead with CISA itself
        names_seen = ["CISA KEV"] + [n for n in names_seen if n != "CISA KEV"]
    lines.append("📰 " + esc(names_seen[0]) + (f" +{len(names_seen) - 1}" if len(names_seen) > 1 else ""))
    if typ == "kev":
        buttons = [("🔎 NVD", nvd_link(cves[0])),
                   ("🛡 CISA KEV", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog")]
    elif typ == "poc":
        buttons = ([("💥 View exploit", first["link"])] if first["link"].startswith("http") else [])
        buttons.append(("🔎 NVD", nvd_link(cves[0])))
    else:
        buttons = article_buttons(first["link"], cves, kev, first["source_type"])
    return {"text": "\n".join(lines), "buttons": buttons}


def render_group(vendor, findings, kev, info, epss, hits=()):
    """One compact message for several plain new CVEs from the same vendor."""
    by_cve = {}
    for f in findings:
        by_cve.setdefault(f["cve"], f)
    lines = [("👀 " if hits else "") + f"🆕 <b>{len(by_cve)} new CVEs · {esc(vendor)}</b>"]
    for cve in list(by_cve)[:8]:
        bits = facts_for(cve, info, epss)
        lines.append(f"• <code>{cve}</code>" + (f" · {esc(' · '.join(bits))}" if bits else ""))
    if len(by_cve) > 8:
        lines.append(f"…and {len(by_cve) - 8} more")
    srcs = list(dict.fromkeys(f["source"] for f in findings))
    lines.append("📰 " + esc(srcs[0]) + (f" +{len(srcs) - 1}" if len(srcs) > 1 else ""))
    buttons, seen_links = [], set()
    for f in findings:
        if f["link"].startswith("http") and f["link"] not in seen_links and len(buttons) < 3:
            seen_links.add(f["link"])
            buttons.append((f"📖 {f['source'][:18]}", f["link"]))
    buttons.append(("🔎 NVD", nvd_link(next(iter(by_cve)))))
    return {"text": "\n".join(lines), "buttons": buttons}


def render_malware_news(f):
    """Threat profile card for a malware article that names no CVE."""
    lines = ["🧬 <b>MALWARE ACTIVITY · NO CVE</b>", DIVIDER, f"<b>{esc(f['title'])}</b>", ""]
    lines.append(f"🦠 <b>Family:</b> {esc(', '.join(f['malware'])) if f['malware'] else 'not named'}")
    types = f.get("mtypes") or []
    lines.append(f"🏷 <b>Type:</b> {esc(', '.join(types)) if types else 'not stated'}")
    delivery = f.get("delivery") or []
    lines.append(f"📨 <b>Delivery:</b> {esc(', '.join(delivery)) if delivery else 'not stated'}")
    if f.get("summary"):
        lines += ["", "📝 <b>Summary</b>", f"<blockquote>{esc(f['summary'])}</blockquote>"]
    lines += ["", f"📰 {esc(f['source'])}", f"🕒 {found_time(f)}"]
    buttons = [("📖 Read article", f["link"])] if f["link"].startswith("http") else []
    return {"text": "\n".join(lines), "buttons": buttons}


def build_digest(state, kev, since, api_key):
    """Group the last day's findings by CVE and write the digest messages."""
    recent = [f for f in state.get("findings", []) if (parse_time(f["time"]) or since) >= since]
    news_only = [f for f in recent if f["kind"] == "malware_news"]
    recent = [f for f in recent if f["kind"] != "malware_news"]
    if not SETTINGS["malware_news"]:  # switched off in sources.json -> CVE items only
        news_only = []
    if not recent and not news_only:
        return [f"📋 <b>Daily threat digest · {now_utc().astimezone(IST):%d %b %Y}</b>\n"
                "Nothing new in the last 24 hours across all sources."]

    by_cve = {}
    for f in recent:
        c = by_cve.setdefault(f["cve"], {"kinds": set(), "sources": {}, "malware": set(),
                                         "confirmed": False, "ransomware": False, "findings": []})
        c["findings"].append(f)
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
        c["vendor"], c["watch"] = vendor_and_watch(c["findings"], {}, kev)

    epss = epss_lookup(sorted(by_cve)) if by_cve else {}

    def rank(item):
        cve, c = item
        return (bool(c["watch"]), c["in_kev"], c["confirmed"], "poc" in c["kinds"],
                len(c["sources"]), epss.get(cve, 0))

    ordered = sorted(by_cve.items(), key=rank, reverse=True)
    for cve, _ in ordered[:MAX_DIGEST_LOOKUPS]:
        c = by_cve[cve]
        c["nvd"] = nvd_lookup(state, cve, api_key)
        c["vendor"], c["watch"] = vendor_and_watch(c["findings"], {cve: c["nvd"]}, kev)  # now with NVD text

    def one_line(cve, c, show_vendor=True):
        """One line per CVE: id, vendor, the key facts, and a link to the first source."""
        nvd = c.get("nvd") or {}
        k = kev.get(cve, {})
        bits = []
        if show_vendor:
            label = f"{k.get('vendorProject', '')} {k.get('product', '')}".strip() or c.get("vendor", "")
            if label:
                bits.append(label)
        if nvd.get("cvss") is not None:
            bits.append(f"CVSS {nvd['cvss']}")
        elif nvd.get("found") is False:
            bits.append("🆕 not in NVD yet")
        if c["in_kev"]:
            bits.append("KEV")
        if c["ransomware"]:
            bits.append("ransomware")
        if c["malware"]:
            bits.append("🦠 " + ", ".join(sorted(c["malware"])[:2]))
        elif c["confirmed"] and not c["in_kev"]:
            bits.append("confirmed exploited")
        elif "exploited" in c["kinds"] and not c["in_kev"]:
            bits.append("exploited")
        if "poc" in c["kinds"]:
            bits.append("public exploit")
        if epss.get(cve, 0) >= 0.1:
            bits.append(f"EPSS {epss[cve] * 100:.0f}%")
        if len(c["sources"]) > 1:
            bits.append(f"{len(c['sources'])} sources")
        url = next(iter(c["sources"].values()), "")
        arrow = f' <a href="{html.escape(url, quote=True)}">↗</a>' if url.startswith("http") else ""
        return f"• {cve_link(cve)}" + (f" · {esc(' · '.join(bits))}" if bits else "") + arrow

    watch_items = [x for x in ordered if x[1]["watch"]]
    ordered = [x for x in ordered if not x[1]["watch"]]  # watchlist items get their own section
    sections = [
        ("👀 Your watchlist", watch_items),
        ("🔴 New in CISA KEV", [x for x in ordered if "kev" in x[1]["kinds"]]),
        ("🦠 Linked to malware", [x for x in ordered if "kev" not in x[1]["kinds"]
                                   and ("malware" in x[1]["kinds"] or x[1]["malware"])]),
        ("⚠️ Exploitation reported", [x for x in ordered if "exploited" in x[1]["kinds"]
                                      and not (x[1]["kinds"] & {"kev", "malware"})
                                      and not x[1]["malware"]]),
        ("💥 Public exploits published", [x for x in ordered if "poc" in x[1]["kinds"]
                                           and not (x[1]["kinds"] & {"kev", "malware", "exploited"})
                                           and not x[1]["malware"]]),
        ("🆕 Other new CVEs in the news", [x for x in ordered if x[1]["kinds"] == {"cve"}]),
    ]
    sources_count = len({f["source"] for f in recent + news_only})
    header = (f"📋 <b>Daily threat digest · {now_utc().astimezone(IST):%d %b %Y}</b>\n"
              f"{len(by_cve)} CVEs and {len(news_only)} malware stories from {sources_count} sources "
              "in the last 24 hours. Most urgent first.")
    pieces = [header]
    min_group = SETTINGS["min_group"]
    for title, items in sections:
        if items:
            pieces.append(f"\n<b>{title} ({len(items)})</b>")
            if title.startswith(("🆕", "👀")) and min_group:  # one block per busy vendor
                by_vendor = {}
                for x in items:
                    by_vendor.setdefault(x[1]["vendor"], []).append(x)
                busy = {v: xs for v, xs in by_vendor.items() if v and len(xs) >= min_group}
                for vendor, xs in sorted(busy.items(), key=lambda kv: -len(kv[1])):
                    pieces.append(f"▸ <b>{esc(vendor)}</b> ({len(xs)})")
                    pieces += [one_line(cve, c, show_vendor=False) for cve, c in xs[:BLOCK_LINES]]
                    if len(xs) > BLOCK_LINES:
                        pieces.append("   +" + str(len(xs) - BLOCK_LINES) + " more: "
                                      + esc(", ".join(cve for cve, _ in xs[BLOCK_LINES:BLOCK_LINES + 15])))
                items = [x for x in items if x[1]["vendor"] not in busy]
            pieces += [one_line(cve, c) for cve, c in items]
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

def send_telegram(token, chat_id, text, buttons=None, silent=False):
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    fields = {"chat_id": chat_id, "text": text[:4096], "parse_mode": "HTML",
              "disable_web_page_preview": "true"}
    if silent:  # delivered without a notification sound
        fields["disable_notification"] = "true"
    if buttons:  # one row of tap-able link buttons under the message
        fields["reply_markup"] = json.dumps(
            {"inline_keyboard": [[{"text": label, "url": u} for label, u in buttons]]})
    payload = urllib.parse.urlencode(fields).encode()
    for _ in range(3):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, data=payload), timeout=30) as resp:
                try:
                    return json.loads(resp.read().decode())["result"]["message_id"]  # kept so it can be edited later
                except (ValueError, KeyError, TypeError):
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


def edit_telegram(token, chat_id, message_id, text, buttons=None):
    """Change a message we sent earlier. True = done, "gone" = it no longer exists, False = failed."""
    url = f"https://api.telegram.org/bot{token}/editMessageText"
    fields = {"chat_id": chat_id, "message_id": message_id, "text": text[:4096],
              "parse_mode": "HTML", "disable_web_page_preview": "true"}
    if buttons:
        fields["reply_markup"] = json.dumps(
            {"inline_keyboard": [[{"text": label, "url": u} for label, u in buttons]]})
    payload = urllib.parse.urlencode(fields).encode()
    for _ in range(3):
        try:
            urllib.request.urlopen(urllib.request.Request(url, data=payload), timeout=30)
            return True
        except urllib.error.HTTPError as err:
            body = err.read().decode(errors="replace")
            low = body.lower()
            if err.code == 429:
                time.sleep(json.loads(body).get("parameters", {}).get("retry_after", 5) + 1)
                continue
            if err.code == 400 and "not modified" in low:
                return True  # nothing to change
            if err.code == 400 and ("not found" in low or "message_id_invalid" in low
                                    or "can't be edited" in low):
                return "gone"
            if err.code == 400 and fields.get("parse_mode") and "parse" in low:
                fields.pop("parse_mode")
                fields["text"] = html.unescape(re.sub(r"<[^>]+>", "", fields["text"]))
                payload = urllib.parse.urlencode(fields).encode()
                continue
            log(f"Telegram edit error {err.code}: {body}")
            return False
        except urllib.error.URLError as err:
            log(f"Telegram connection error: {err}")
            time.sleep(3)
    return False


def deliver(state, queue, token, chat_id, dry_run):
    """Send (or edit) every queued message, saving progress after each one.
    A CVE's first alert starts a thread; later updates edit that message. Returns (sent, failed)."""
    sent, failed = 0, []
    for i, m in enumerate(queue):
        mid = False
        if dry_run:
            mark = "  (edits its earlier message)" if m.get("edit") else "  (silent)" if m.get("silent") else ""
            print("\n" + "-" * 60 + mark + "\n" + m["text"])
            if m.get("buttons"):
                print("   " + "  ".join(f"[ {label} ]" for label, _ in m["buttons"]))
            mid = m.get("edit") or 9000 + i
        elif m.get("edit"):
            result = edit_telegram(token, chat_id, m["edit"], m["text"], m.get("buttons"))
            if result == "gone":  # the old message was deleted: send the update as a new one
                mid = send_telegram(token, chat_id, m["text"], m.get("buttons"))
            elif result:
                mid = m["edit"]
        else:
            mid = send_telegram(token, chat_id, m["text"], m.get("buttons"), m.get("silent", False))
        if mid:
            sent += 1
            for key, when in m.get("keys", []):  # save_state() rebuilds this dict, so look it up each time
                state.setdefault("alerted", {})[key] = when
            if m.get("thread"):
                state.setdefault("threads", {})[m["thread"]["cve"]] = {
                    "message_id": mid, "events": m["thread"]["events"],
                    "time": now_utc().isoformat(timespec="seconds")}
        else:
            failed.append(m)
        state["outbox"] = failed + queue[i + 1:]
        if not dry_run:
            save_state(state)
            if mid and i + 1 < len(queue):
                time.sleep(1)
    return sent, failed


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
    configure(config)
    state = load_state()
    brand_new = not state
    state.setdefault("findings", [])
    run_id = now_utc().isoformat()
    if "last_digest" not in state:  # first digest comes at the next scheduled time, not now
        state["last_digest"] = now_utc().astimezone(IST).date().isoformat()
        state["last_digest_time"] = now_utc().isoformat(timespec="seconds")

    started = time.monotonic()

    def safely(name, fn, *args, default=None):
        """Run one source; if it fails for any reason, log it and carry on with the rest."""
        try:
            return fn(*args)
        except Exception as err:
            log(f"{name} failed: {type(err).__name__}: {err}")
            return default

    kev = safely("KEV check", check_kev, state, config["kev_url"], run_id, default={}) or {}
    reached = safely("Feeds", check_feeds, state, config["feeds"], run_id, default=0) or 0
    if time.monotonic() - started < SOCIAL_CUTOFF_MINUTES * 60:
        safely("Bluesky", check_bluesky, state, config, run_id)
        safely("X", check_x, state, config, run_id)
        safely("GitHub", check_github, state, config, run_id)
    else:
        log("This run is already slow: skipping Bluesky, X and GitHub until the next run")

    nvd_budget(NVD_BUDGET_ALERTS)
    messages = instant_alerts(state, kev, run_id, nvd_key)
    if len(messages) > MAX_INSTANT_ALERTS_PER_RUN:
        extra = messages[MAX_INSTANT_ALERTS_PER_RUN:]
        messages = messages[:MAX_INSTANT_ALERTS_PER_RUN]
        alerted = state.setdefault("alerted", {})
        for m in extra:  # these are covered by the daily digest instead
            for key, when in m.get("keys", []):
                alerted[key] = when
        messages.append(f"…and {len(extra)} more new items this run. They'll all be in the daily digest.")

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
        nvd_budget(NVD_BUDGET_DIGEST)
        messages += build_digest(state, kev, since, nvd_key)
        state["last_digest"] = now_utc().astimezone(IST).date().isoformat()
        state["last_digest_time"] = now_utc().isoformat(timespec="seconds")

    # Delivery. Every message goes through the outbox, which is saved before sending and after each
    # message, so a run that is cut short neither loses alerts nor sends them twice. A CVE only counts
    # as "alerted" once Telegram has accepted the message; failed messages are retried next run.
    now_iso = now_utc().isoformat(timespec="seconds")
    queue = []
    for m in state.get("outbox", []):
        age = now_utc() - (parse_time(m.get("queued")) or now_utc())
        if age > timedelta(hours=OUTBOX_MAX_HOURS):
            log("Dropping an undelivered message older than "
                f"{OUTBOX_MAX_HOURS} h (its finding is still in the digest)")
            continue
        queue.append(m)
    for m in messages:
        m = dict(m) if isinstance(m, dict) else {"text": m}
        m.setdefault("keys", [])
        m["queued"] = now_iso
        queue.append(m)

    state["outbox"] = list(queue)
    if not dry_run:
        save_state(state)
    sent, failed = deliver(state, queue, token, chat_id, dry_run)
    if failed:
        log(f"{len(failed)} message(s) could not be delivered; they will be retried next run")

    sources_watched = (1 + len(config["feeds"]) + len(config.get("github", {}).get("commit_repos", []))
                       + (1 if config.get("github", {}).get("poc_queries") else 0)
                       + (1 if config.get("github", {}).get("advisory_severities") else 0)
                       + (1 if os.environ.get("BLUESKY_HANDLE") else 0)
                       + (1 if os.environ.get("X_BEARER_TOKEN") else 0))
    try:
        write_dashboard(state, kev, sources_watched)
    except Exception as err:  # the dashboard is a nice-to-have; never let it stop alerts
        log(f"Dashboard data not written: {err}")

    # Ask the workflow to back up seen.json to the repo about once a day.
    last_backup = parse_time(state.get("last_backup"))
    if not last_backup or now_utc() - last_backup > timedelta(hours=BACKUP_EVERY_HOURS):
        state["last_backup"] = now_utc().isoformat(timespec="seconds")
        (HERE / "backup_due").write_text("1", encoding="utf-8")
    save_state(state)
    log(f"Done in {time.monotonic() - started:.0f} s. {reached}/{len(config['feeds'])} feeds read, "
        f"{len(queue)} messages, {sent} sent, {len(failed)} waiting.")


if __name__ == "__main__":
    sys.exit(main())
