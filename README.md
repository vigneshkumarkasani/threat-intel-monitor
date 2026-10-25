# Threat Intel Monitor

A personal early-warning feed for vulnerability intelligence. Every 20 minutes it checks over 40 news, research, vendor, government, exploit and social sources, plus the CISA KEV catalog. It sends a Telegram alert within minutes of publication whenever:

- a **new CVE** appears in any news, research, vendor or government source,
- a CVE is reported **exploited**, or **linked to malware**,
- a **malware article** is published, even with no CVE, or
- CISA adds a CVE to the **KEV catalog**.

A daily digest at 9:00 AM IST ranks the last 24 hours by urgency, and a live dashboard on my portfolio shows the last 7 days. It runs on GitHub Actions, triggered by cron-job.org, so no computer needs to stay on.

## Sources

| Type | Sources |
|---|---|
| Exploitation catalog | CISA Known Exploited Vulnerabilities (KEV) |
| News | The Hacker News, BleepingComputer, SecurityWeek, Help Net Security, Dark Reading, The Record, Cyber Security News, GBHackers, Infosecurity Magazine |
| Threat research | Google Threat Intelligence (Mandiant), Unit 42, Rapid7, watchTowr Labs, Cisco Talos, Microsoft Security Blog, Kaspersky Securelist, Check Point Research, Huntress, SANS ISC, AWS Security Blog, Sophos |
| Vendor advisories | Cisco, Fortinet PSIRT, Palo Alto Networks, Google Chrome Releases, Oracle, GitHub Advisory Database (critical and high) |
| Government | Canadian Centre for Cyber Security (advisories for most major vendors), CERT-EU |
| Social | Mastodon (#cve, #zeroday, #ransomware, #malware, #threatintel), Bluesky; optional X/Twitter (paid) |
| Enrichment | NVD (CVSS, description), FIRST EPSS (exploit probability) |

Feeds are listed in `sources.json`. To add one, copy a line and change the name, type and URL. PoC and public-exploit sources are switched off. The GitHub advisory database uses GitHub's official API with the token Actions provides automatically.

## Alerts

| Alert | Style | Meaning |
|---|---|---|
| 🔴 New in CISA KEV | Detailed | CISA confirms exploitation; shows product, due date, required action, ransomware use |
| 🦠 Malware linked to CVE | Detailed | A CVE mentioned alongside malware or a named family (Qilin, XMRig, Cobalt Strike…) |
| 🛑 Vendor / government confirms exploitation | Detailed | An official advisory says it is exploited |
| ⚠️ Exploitation reported | Detailed | News, research or social posts report in-the-wild exploitation |
| 🧬 Malware activity, no CVE | Threat profile | Family, type (ransomware, infostealer, botnet…), delivery method (phishing, ClickFix, malicious packages…) |
| 🆕 New CVE | Card | First time a CVE appears in any source |

Every CVE alert includes CVSS with severity, EPSS, KEV status, a short summary, the time in IST and buttons to the article and NVD.

A CVE is alerted again only when its news gets more serious: new CVE, then exploited, then malware, then KEV. When ten sites copy one story, you get one alert. Social media alerts only on exploitation or malware, because bots there announce every CVE.

## Accuracy rules

Malware and exploitation words only count within a couple of sentences of the CVE, in the same paragraph. The bot ignores:

- **Denials:** "no evidence it was exploited", "not in the KEV catalog"
- **Hypotheticals:** "could allow an attacker to install malware"
- **Related-story links:** an unrelated ransomware headline lower on the page

## Live dashboard

After each run the bot writes `feed.json` (the last 7 days of findings plus summary numbers) to the `dashboard-data` branch. That branch holds a single commit that is replaced every run, so it never builds up history. My portfolio page reads it to show the week's findings, top malware families and busiest sources.

## Setup

Required secrets (**Settings → Secrets and variables → Actions**):

- `TELEGRAM_BOT_TOKEN`, from [@BotFather](https://t.me/BotFather)
- `TELEGRAM_CHAT_ID`: message your bot, then open `https://api.telegram.org/bot<TOKEN>/getUpdates`

Optional secrets:

| Secret | Turns on | Cost |
|---|---|---|
| `NVD_API_KEY` | Faster CVSS lookups ([request one](https://nvd.nist.gov/developers/request-an-api-key)) | Free |
| `BLUESKY_HANDLE` + `BLUESKY_APP_PASSWORD` | Bluesky search every 15 minutes | Free |
| `X_BEARER_TOKEN` | X/Twitter search for CVE posts about exploitation or malware | About $0.005 per post read; capped by `max_reads_per_day` in `sources.json` |

Run it once from **Actions → Threat Intel Monitor → Run workflow**. Tick **Send the daily digest now** to see a digest immediately.

## How it runs

- **Schedule:** cron-job.org starts the workflow every 20 minutes through GitHub's API. GitHub's own schedule is kept as a backup. The workflow's concurrency setting stops runs from overlapping.
- **Memory:** `seen.json` is kept in GitHub's cache between runs and backed up to the repo about once a day.
- **First read:** the first time a source is read, its existing items are saved without alerting, so there's no flood of old stories.
- **Testing:** run `python3 monitor.py` without secrets to print messages instead of sending them.

## Reliability

- **Feeds are downloaded in parallel** with a 15-second limit each, so a slow site can't hold up the run. Any error from one feed (timeouts, dropped connections, broken XML) skips just that feed.
- **Every source is isolated.** If KEV, a feed, Bluesky, X or GitHub fails, the others still run. Optional sources are skipped if a run is already slow.
- **NVD has a time budget** (90 seconds for instant alerts, 120 for the digest) and is skipped after three failures in a row. When NVD is down, alerts still go out, just without CVSS.
- **Nothing is marked as alerted until Telegram accepts the message.** Undelivered messages wait in an outbox inside `seen.json` and are retried on later runs for up to 12 hours. The outbox is saved before and after each message, so a run that's cut short neither loses alerts nor sends them twice.
- **Article links are remembered for 45 days by date**, so old stories in slow-moving feeds never come back as new.
- **Memory is always saved**, even when a run fails or times out. The script stops at 11 minutes so there's time to save.
- **You're told when something breaks:** a failed or cut-short run sends a short Telegram warning (at most about one an hour) with a link to the run.

## Files

| File | What it is |
|---|---|
| `monitor.py` | The script (Python standard library only) |
| `sources.json` | Feeds, GitHub and social media settings |
| `malware_names.txt` | Malware families and groups to recognise |
| `.github/workflows/monitor.yml` | Schedule, memory, dashboard publishing and daily backup |
| `seen.json` | Created automatically: what has been reported, plus any messages waiting to be delivered |
