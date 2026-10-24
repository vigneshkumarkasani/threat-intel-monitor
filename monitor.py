"""
Threat Intel Monitor
--------------------
Checks two kinds of sources and sends new findings to Telegram:

  1. CISA's Known Exploited Vulnerabilities (KEV) catalog -> newly exploited CVEs
  2. Security news RSS feeds -> articles that name a CVE AND mention malware,
     ransomware or in-the-wild exploitation

It remembers what it has already sent in seen.json, so you never get the
same alert twice. Uses only Python's standard library: nothing to install.

Settings come from environment variables (GitHub "secrets"):
  TELEGRAM_BOT_TOKEN   token from @BotFather
  TELEGRAM_CHAT_ID     your chat ID
If either is missing, the script runs in DRY-RUN mode and just prints
the alerts instead of sending them. Handy for testing.
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
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Settings you might want to change
# ---------------------------------------------------------------------------

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

NEWS_FEEDS = {
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "SecurityWeek": "https://www.securityweek.com/feed/",
}

# Words that mean "this article is about malware or an attack campaign".
MALWARE_WORDS = [
    "malware", "ransomware", "botnet", "backdoor", "trojan", "stealer",
    "infostealer", "loader", "dropper", "cryptominer", "crypto miner",
    "coinminer", "xmrig", "webshell", "web shell", "rootkit", "bootkit",
    "spyware", "wiper", "rat", "implant", "command-and-control",
]

# Words that mean "attackers are already using this bug".
EXPLOIT_WORDS = [
    "actively exploited", "exploited in the wild", "in-the-wild",
    "in the wild", "zero-day", "0-day", "under attack", "exploitation attempts",
    "active exploitation", "being exploited", "exploited in attacks",
]

STATE_FILE = Path(__file__).with_name("seen.json")
MAX_ALERTS_PER_RUN = 25          # stops a flood of messages on a busy day
MAX_REMEMBERED_ARTICLES = 3000   # keeps seen.json small

CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
USER_AGENT = "Mozilla/5.0 (compatible; ThreatIntelMonitor/1.0; +https://github.com)"


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def log(message):
    print(f"[{datetime.now(timezone.utc):%Y-%m-%d %H:%M:%S} UTC] {message}", flush=True)


def fetch(url, timeout=30):
    """Download a URL and return the raw bytes."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def word_regex(words):
    """Build one case-insensitive regex that matches any of the words as whole words."""
    escaped = sorted((re.escape(w) for w in words), key=len, reverse=True)
    return re.compile(r"(?<![\w-])(" + "|".join(escaped) + r")(?![\w-])", re.IGNORECASE)


MALWARE_RE = word_regex(MALWARE_WORDS)
EXPLOIT_RE = word_regex(EXPLOIT_WORDS)


def strip_html(text):
    text = re.sub(r"<[^>]+>", " ", text or "")
    return re.sub(r"\s+", " ", html.unescape(text)).strip()


def nvd_link(cve_id):
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}"


def load_state():
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            log("seen.json was unreadable, starting fresh")
    return {}


def save_state(state):
    state["articles"] = state.get("articles", [])[-MAX_REMEMBERED_ARTICLES:]
    state["last_run"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    STATE_FILE.write_text(json.dumps(state, indent=1, sort_keys=True), encoding="utf-8")


# ---------------------------------------------------------------------------
# Source 1: CISA KEV
# ---------------------------------------------------------------------------

def check_kev(state):
    """Return alert messages for KEV entries we haven't seen before."""
    data = json.loads(fetch(KEV_URL))
    entries = data.get("vulnerabilities", [])
    log(f"KEV catalog has {len(entries)} entries")

    first_run = "kev" not in state
    seen = set(state.get("kev", []))
    new_entries = [e for e in entries if e.get("cveID") not in seen]
    state["kev"] = sorted(seen | {e.get("cveID") for e in entries if e.get("cveID")})

    if first_run:
        # Don't send 1,500 messages the first time: just remember everything.
        log("First run: saved the current KEV list without sending alerts")
        return []

    new_entries.sort(key=lambda e: e.get("dateAdded", ""))
    alerts = []
    for e in new_entries:
        cve = e.get("cveID", "")
        ransomware = e.get("knownRansomwareCampaignUse", "Unknown")
        lines = [
            "🔴 <b>New CISA KEV entry</b>",
            f'<a href="{nvd_link(cve)}">{html.escape(cve)}</a>: '
            f"{html.escape(e.get('vulnerabilityName', ''))}",
            f"<b>Product:</b> {html.escape(e.get('vendorProject', ''))} "
            f"{html.escape(e.get('product', ''))}",
            f"<b>Added:</b> {html.escape(e.get('dateAdded', ''))} · "
            f"<b>Federal due date:</b> {html.escape(e.get('dueDate', ''))}",
        ]
        if ransomware.lower() == "known":
            lines.append("🟠 <b>Known ransomware use</b>")
        if e.get("shortDescription"):
            lines.append(html.escape(e["shortDescription"][:500]))
        alerts.append("\n".join(lines))
    log(f"KEV: {len(alerts)} new entries")
    return alerts


# ---------------------------------------------------------------------------
# Source 2: security news RSS feeds
# ---------------------------------------------------------------------------

def parse_feed(raw):
    """Yield (title, link, summary) from an RSS or Atom feed."""
    root = ET.fromstring(raw)
    atom = "{http://www.w3.org/2005/Atom}"
    for item in root.iter("item"):                       # RSS 2.0
        yield (
            (item.findtext("title") or "").strip(),
            (item.findtext("link") or "").strip(),
            item.findtext("description") or "",
        )
    for entry in root.iter(f"{atom}entry"):              # Atom
        link_el = entry.find(f"{atom}link")
        yield (
            (entry.findtext(f"{atom}title") or "").strip(),
            link_el.get("href", "").strip() if link_el is not None else "",
            entry.findtext(f"{atom}summary") or entry.findtext(f"{atom}content") or "",
        )


def check_news(state):
    """Return alert messages for new articles that tie a CVE to malware or exploitation."""
    seen = set(state.get("articles", []))
    remembered = list(state.get("articles", []))
    feeds_read = set(state.get("feeds_read", []))
    alerts = []

    for source, url in NEWS_FEEDS.items():
        try:
            items = list(parse_feed(fetch(url)))
        except (urllib.error.URLError, ET.ParseError, TimeoutError, OSError) as err:
            log(f"Could not read {source}: {err}")
            continue
        log(f"{source}: {len(items)} articles in feed")
        # The first time a feed is read, just remember its articles (no backlog flood).
        first_run = source not in feeds_read
        if first_run:
            log(f"{source}: first successful read, saving articles without alerts")
        feeds_read.add(source)

        for title, link, summary in items:
            if not link or link in seen:
                continue
            seen.add(link)
            remembered.append(link)

            text = f"{title} {strip_html(summary)}"
            cves = sorted({c.upper() for c in CVE_PATTERN.findall(text)})
            if not cves:
                continue
            malware_hits = sorted({m.lower() for m in MALWARE_RE.findall(text)})
            exploit_hits = sorted({m.lower() for m in EXPLOIT_RE.findall(text)})
            if not malware_hits and not exploit_hits:
                continue
            if first_run:
                continue  # remember, but don't alert on the backlog

            icon = "🦠" if malware_hits else "⚠️"
            heading = "Malware linked to CVE" if malware_hits else "Exploitation reported"
            cve_links = ", ".join(f'<a href="{nvd_link(c)}">{c}</a>' for c in cves[:8])
            lines = [
                f"{icon} <b>{heading}</b> · {html.escape(source)}",
                f'<a href="{html.escape(link, quote=True)}">{html.escape(title)}</a>',
                f"<b>CVEs:</b> {cve_links}",
            ]
            if malware_hits:
                lines.append(f"<b>Malware terms:</b> {html.escape(', '.join(malware_hits))}")
            if exploit_hits:
                lines.append(f"<b>Exploitation terms:</b> {html.escape(', '.join(exploit_hits))}")
            alerts.append("\n".join(lines))

    state["articles"] = remembered
    state["feeds_read"] = sorted(feeds_read)
    log(f"News: {len(alerts)} new matching articles")
    return alerts


# ---------------------------------------------------------------------------
# Telegram
# ---------------------------------------------------------------------------

def send_telegram(token, chat_id, text):
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = urllib.parse.urlencode({
        "chat_id": chat_id,
        "text": text[:4000],
        "parse_mode": "HTML",
        "disable_web_page_preview": "true",
    }).encode()
    for attempt in range(3):
        try:
            urllib.request.urlopen(urllib.request.Request(url, data=payload), timeout=30)
            return True
        except urllib.error.HTTPError as err:
            body = err.read().decode(errors="replace")
            if err.code == 429:  # Telegram says "slow down"
                wait = json.loads(body).get("parameters", {}).get("retry_after", 5)
                time.sleep(wait + 1)
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
    dry_run = not (token and chat_id)
    if dry_run:
        log("DRY-RUN: Telegram settings not found, alerts will be printed only")

    state = load_state()
    first_run = not state
    alerts = []

    try:
        alerts += check_kev(state)
    except Exception as err:  # one broken source shouldn't stop the others
        log(f"KEV check failed: {err}")
    alerts += check_news(state)

    if first_run:
        alerts = [
            "✅ <b>Threat Intel Monitor is running.</b>\n"
            f"Watching the CISA KEV catalog ({len(state.get('kev', []))} entries) and "
            f"{len(state.get('feeds_read', []))} of {len(NEWS_FEEDS)} news feeds. "
            "You'll get a message here when something new shows up."
        ]

    if len(alerts) > MAX_ALERTS_PER_RUN:
        extra = len(alerts) - MAX_ALERTS_PER_RUN
        alerts = alerts[:MAX_ALERTS_PER_RUN]
        alerts.append(f"…and {extra} more new items this run. Check the KEV catalog and feeds.")

    sent = 0
    for message in alerts:
        if dry_run:
            print("\n" + "-" * 60 + "\n" + message)
        elif send_telegram(token, chat_id, message):
            sent += 1
            time.sleep(1)  # be polite to Telegram

    save_state(state)
    log(f"Done. {len(alerts)} alerts, {sent} sent.")


if __name__ == "__main__":
    sys.exit(main())
