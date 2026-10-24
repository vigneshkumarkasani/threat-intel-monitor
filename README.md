# Threat Intel Monitor

A small automation that watches for **actively exploited CVEs** and **malware news that names a CVE**, and sends an alert to Telegram as soon as something new appears. It runs every hour on GitHub Actions, so no computer needs to stay on.

## What it watches

| Source | What triggers an alert |
|---|---|
| [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Any CVE newly added to the catalog, flagged if it has known ransomware use |
| The Hacker News, BleepingComputer, SecurityWeek (RSS) | An article that names a CVE **and** mentions malware (ransomware, botnet, stealer, miner, webshell…) or in-the-wild exploitation (zero-day, actively exploited…) |

Articles that mention a CVE with no sign of attacks (for example, a routine patch release) are skipped, so the alerts stay focused on what attackers are actually using.

## How it works

1. GitHub Actions starts the job every hour.
2. `monitor.py` downloads the KEV catalog and the news feeds.
3. It compares them with `seen.json`, the list of items it has already reported.
4. Anything new is sent to Telegram, and `seen.json` is saved back to the repository.

On its very first run it records everything that already exists without alerting, then sends a single "monitor is running" message. After that you only hear about new items.

The script uses only Python's standard library, so there is nothing to install.

## Example alerts

```
🔴 New CISA KEV entry
CVE-2026-110936: Siemens Software Center Uncontrolled Search Path Element
Product: Siemens Software Center
Added: 2026-10-20 · Federal due date: 2026-10-23

🦠 Malware linked to CVE · SecurityWeek
Plex2Shell Exploit Chain Weaponized Against Plex Servers
CVEs: CVE-2026-96652, CVE-2026-96656
Malware terms: cryptominer, xmrig
```

## Setup

1. Create a bot with [@BotFather](https://t.me/BotFather) on Telegram and copy its token.
2. Send your bot any message, then open `https://api.telegram.org/bot<TOKEN>/getUpdates` and copy the `chat` → `id` number.
3. In this repo, go to **Settings → Secrets and variables → Actions** and add two secrets: `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID`.
4. Go to the **Actions** tab, pick **Threat Intel Monitor**, and click **Run workflow** to test it.

To test locally without Telegram, just run `python monitor.py`: with no secrets set it prints the alerts instead of sending them.

## Ideas for next versions

- Add EPSS scores from FIRST to show how likely each CVE is to be exploited
- A once-a-day summary message
- A watchlist so only chosen vendors or products trigger alerts
- More feeds (vendor advisories, CERT bulletins)
