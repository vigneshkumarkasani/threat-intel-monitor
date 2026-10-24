# Threat Intel Monitor

An early-warning feed for vulnerability intelligence. Every 5 minutes it checks 31 news, research, vendor, government and social sources, plus the CISA KEV catalog, and sends a Telegram alert within minutes of publication whenever:

- a **new CVE** appears in any news, research or vendor source,
- a CVE is reported **exploited**, or **linked to malware**,
- a **malware article** is published, even with no CVE, or
- CISA adds a CVE to the **KEV catalog**.

A daily digest at 9:00 AM IST ranks the last 24 hours by urgency. It runs on GitHub Actions, so no computer needs to stay on.

## Sources

| Type | Sources |
|---|---|
| Exploitation catalog | CISA Known Exploited Vulnerabilities (KEV) |
| News | The Hacker News, BleepingComputer, SecurityWeek, Help Net Security, Dark Reading, The Record, Cyber Security News, GBHackers, Infosecurity Magazine |
| Threat research | Google Threat Intelligence (Mandiant), Unit 42, Rapid7, watchTowr Labs, Cisco Talos, Microsoft Security Blog, Kaspersky Securelist, Check Point Research, Huntress, SANS ISC, AWS Security Blog, Sophos |
| Vendor advisories | Cisco, Fortinet PSIRT, Palo Alto Networks, Google Chrome Releases |
| Government | CISA Cybersecurity Advisories |
| Social | Mastodon (#cve, #zeroday, #ransomware, #malware, #threatintel); optional Bluesky (free) and X/Twitter (paid) |
| Enrichment | NVD (CVSS, description), FIRST EPSS (exploit probability) |

All sources are listed in `sources.json`. To add one, copy a line and change the name, type and URL.

## Alerts

| Alert | Meaning |
|---|---|
| 🔴 New CISA KEV entry | CISA confirms exploitation, flagged if ransomware uses it |
| 🦠 Malware linked to CVE | A CVE mentioned alongside malware or a named family (Qilin, XMRig, Cobalt Strike…) |
| 🛑 Vendor confirms exploitation | The vendor's own advisory says it is exploited |
| ⚠️ Exploitation reported | News, research or social posts report in-the-wild exploitation |
| 🆕 New CVE in the news / vendor advisory | First time a CVE appears in any source |
| 📰 Malware news | A malware or ransomware article without a CVE |

A CVE is alerted again only when its news gets more serious: new CVE, then exploited, then malware, then KEV. When ten sites copy one story, you get one alert. Social media alerts only on exploitation or malware, because bots there announce every CVE.

## Accuracy rules

Malware and exploitation words only count within a couple of sentences of the CVE, in the same paragraph. The bot ignores:

- **Denials:** "no evidence it was exploited", "not in the KEV catalog"
- **Hypotheticals:** "could allow an attacker to install malware"
- **Related-story links:** an unrelated ransomware headline lower on the page

## Setup

Required secrets (**Settings → Secrets and variables → Actions**):

- `TELEGRAM_BOT_TOKEN`, from [@BotFather](https://t.me/BotFather)
- `TELEGRAM_CHAT_ID`: message your bot, then open `https://api.telegram.org/bot<TOKEN>/getUpdates`

Optional secrets:

| Secret | Turns on | Cost |
|---|---|---|
| `NVD_API_KEY` | Faster CVSS lookups in the digest ([request one](https://nvd.nist.gov/developers/request-an-api-key)) | Free |
| `BLUESKY_HANDLE` + `BLUESKY_APP_PASSWORD` | Bluesky search every 15 minutes (Settings → App passwords in Bluesky) | Free |
| `X_BEARER_TOKEN` | X/Twitter search for CVE posts about exploitation or malware | About $0.005 per post read; capped at `max_reads_per_day` in `sources.json` (150 by default, roughly $20–25 a month) |

Run it once from **Actions → Threat Intel Monitor → Run workflow**. Tick **Send the daily digest now** to see a digest immediately.

## How it runs

- **Schedule:** every 5 minutes, which is GitHub's minimum. Busy periods can delay a run.
- **Memory:** `seen.json` is kept in GitHub's cache between runs and backed up to the repo once a day.
- **First read:** the first time a source is read, its existing items are saved without alerting, so there's no flood of old stories.
- **Testing:** run `python monitor.py` without secrets to print messages instead of sending them.

## Files

| File | What it is |
|---|---|
| `monitor.py` | The script (Python standard library only) |
| `sources.json` | Feeds and social media settings |
| `malware_names.txt` | Malware families and groups to recognise |
| `.github/workflows/monitor.yml` | The 5-minute schedule |
| `seen.json` | Created automatically: what has been reported |
