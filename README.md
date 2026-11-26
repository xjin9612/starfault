<p align="center">
  <img src="assets/icon.svg" width="128" height="128" alt="starfault">
</p>

<h1 align="center">starfault</h1>

<p align="center">English | <a href="README.zh-TW.md">繁體中文</a></p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
</p>

starfault is a daily CVE dashboard. It tracks exploited vulnerabilities (CISA KEV), rising EPSS scores and critical CVEs, and the Telegram bot "the Geologist" sends the alerts. It belongs to the same family as starstrata and starcore and shares their layout, components and bot.

- **New KEV entries, right away**: CISA KEV is checked hourly. Each new CVE gets its own alert with the due date and whether forensic triage is required.
- **Daily digest**: new CVEs whose EPSS first crosses the threshold, and new CVEs with CVSS ≥ 9 that have no EPSS yet.
- **Your stack**: when a product on your private list gets a new vulnerability, it goes to the top of the daily digest. The list lives only in a GitHub secret; it never appears on the site, in logs or in the repo.
- **Website**: Today, watched CVEs, the KEV catalog, CVE detail pages (CVSS, EPSS trend, KEV action, affected products, timeline), and the alert rules with threshold calibration. The interface is in Traditional Chinese or English, and CVE titles and descriptions can be translated into the language set in `translation.target`.
- Everything runs on GitHub Actions. State is stored as JSON in the repo; no server or database is needed.

## Before you start

- **Cost**: public repositories use GitHub's standard runners for free ([GitHub Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions)). The hourly workflow runs 24 times a day.
- **Coverage**: the site only lists CVEs that match an alert rule (KEV, rising EPSS, critical). Look up other CVEs on [CVE.org](https://www.cve.org) or [NVD](https://nvd.nist.gov).
- **Alert timing**: GitHub Actions delays scheduled runs under load, and drops some when the load is high enough ([GitHub Docs](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule)). A KEV alert can arrive tens of minutes to a few hours late.
- **Thresholds are provisional**: the `thresholds` values should be calibrated with a week of real data. The "Threshold calibration" table on the Rules page shows how many alerts each threshold would send per day.
- **The Telegram group must be private**: the "Your stack" section of the daily digest reveals your stack. Do not give the group a public username, and keep the invite link private.
- **Gemini free tier**: Google uses content sent to its free services to improve its products, and human reviewers may read it ([Gemini API terms](https://aistudio.google.com/docs/terms)). starfault only sends the public titles and descriptions of CVEs listed on the site, never the stack list.

## Deploy your own

1. Fork this repository and keep it public. When the Actions tab asks whether to enable workflows, enable them.
2. Edit `config.toml`:
   - Set `site.url` to `https://<your-account>.github.io/<repo>/`. With `""`, Telegram messages have no site buttons, and the share preview tags have no URL or image.
   - Set `site.locale` to `zh-TW` or `en` for the site and Telegram messages.
   - Set `translation.target` to the language for CVE titles and descriptions (for example `ja`); `""` turns translation off.
3. Delete every file under `state/` if there are any: they are the original author's state. The first run recreates the directory.
4. Under Settings → Secrets and variables → Actions, create these secrets:

   | Name | Required | Purpose |
   |---|---|---|
   | `TELEGRAM_BOT_TOKEN` | No | Telegram bot token; without it no messages are sent |
   | `TELEGRAM_CHAT_ID` | No | The group that receives messages; see [Telegram](#telegram) |
   | `STARFAULT_WATCHLIST` | No | Your stack list (TOML); see [Your stack](#your-stack) |
   | `GEMINI_API_KEY` | No | Translation (default provider), free from [Google AI Studio](https://aistudio.google.com). Without it the original text is shown |
   | `ANTHROPIC_API_KEY` | No | Uses Claude when `translation.provider` is `anthropic` |

   To post into a topic of a group, also create the repository variable `TELEGRAM_THREAD_ID` on the Variables tab of the same page. It is a variable rather than a secret: GitHub masks secret values in logs ([GitHub Docs](https://docs.github.com/en/actions/concepts/security/secrets)), and a short number such as `7` would mask every matching number in the logs.

5. Under Settings → Pages → Build and deployment, set Source to **GitHub Actions**.
6. First run:
   1. Actions → `Hourly` → Run workflow. The first run only records the KEV snapshot and sends no alerts.
   2. Actions → `Daily` → Run workflow with `backfill_days` set to `30`. This reads the last 30 days of CVEs, so the chart on Today and the calibration table have data.

   Or with `gh`:

   ```sh
   gh workflow run hourly.yml -R <owner>/<repo>
   gh workflow run daily.yml -R <owner>/<repo> -f backfill_days=30
   ```

After that, `Hourly` runs at minute 23 of every hour and `Daily` runs every day at 22:17 UTC (06:17 in `Asia/Taipei`). Each run:

- commits state to `state/` (the hourly run only commits when KEV, the notified list or the watch list changed);
- sends Telegram alerts;
- deploys the site to GitHub Pages.

Full CVE records for KEV entries are fetched 100 per run, so they are complete after about 18 hours. Until then, detail pages use the description from the KEV catalog.

## Telegram

1. Create a bot with [@BotFather](https://t.me/BotFather) and copy the token. You can use `assets/bot-avatar.png` ("the Geologist", shared by the three projects) as the bot picture.
2. Create a private group, add the bot, and send `/start@<bot username>` in the group. Bots have privacy mode on by default and only receive commands addressed to them in groups ([privacy mode](https://core.telegram.org/bots/features#privacy-mode)).
3. Find the chat ID: in the response, look for a message whose `chat.type` is `group` or `supergroup` and use its `chat.id`.

   ```sh
   curl -s "https://api.telegram.org/bot<token>/getUpdates"
   ```

4. Save `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` as secrets.

To post into a topic of a group with Topics enabled:

1. Enable Topics in the group settings. A group with topics is a supergroup; when a basic group is upgraded it gets a new chat ID ([`migrate_to_chat_id`](https://core.telegram.org/bots/api#message)), so update `TELEGRAM_CHAT_ID`.
2. Send `/start@<bot username>` in the target topic.
3. In the `getUpdates` response above, that message's `message.message_thread_id` is the topic ID. Save it as the repository variable `TELEGRAM_THREAD_ID`.

Without `TELEGRAM_THREAD_ID`, messages go to General ([Telegram forums](https://core.telegram.org/api/forum)). If the value is not a positive integer, nothing is sent and the workflow fails.

| Message | When | Sound |
|---|---|---|
| Added to KEV | Checked hourly, one message per CVE, with "Details" and "CISA KEV" buttons | Yes |
| Daily digest | Once a day; not sent when empty | Only when it has a "Your stack" section |
| Failure notice | A workflow failed or timed out, with a link to the run | Yes |

## Your stack

Write the products you care about as TOML and save it as the secret `STARFAULT_WATCHLIST`. See [`watchlist.example.toml`](watchlist.example.toml) for the format:

```toml
[[product]]
name = "Example Proxy"                 # name shown in alerts
match = ["example proxy", "exproxy"]   # ways the product name is written, at least one
vendors = ["example labs"]             # optional: limit to these vendors, to rule out same-name products
note = "front proxy"                   # optional: shown in alerts
```

- Matching uses the affected products and CPEs of CVE records and the product fields of KEV. Case and punctuation do not matter, but terms must match whole words: `quill` does not match `quillstore`.
- Only products are matched, not versions. Alerts include the affected and fixed versions from the CVE so you can judge.
- List every spelling of a product in `match`. Vendors often appear under different names (renames, acquisitions, distributions repackaging the product), so list those in `vendors` too.
- List libraries separately, such as the framework or logging package inside your application; starfault does not scan dependencies.
- New CVEs that match and have CVSS ≥ `watchlist.cvss` (7.0 by default) or no score yet go to the top of the daily digest. When a matching CVE is added to KEV, the alert gets an extra "Matches your stack" line.
- The list never appears on the site, in state files, in Actions logs or in commits: logs do not print product names, matching CVEs or match counts. CVEs that match only your stack are not added to the site; their alerts link to CVE.org and NVD.
- If a daily digest contains only the "Your stack" section and Telegram fails, later runs do not resend it, and the run still succeeds. A failed run or a resend would show in public that something matched.
- For local testing, put the list in `watchlist.toml` at the repository root. It is listed in `.gitignore`.

## Configuration

All settings live in `config.toml`, and every key has a comment. Unknown keys or out-of-range values stop the run with exit code `2`.

| Section | Controls |
|---|---|
| `[thresholds]` | EPSS and CVSS thresholds, how recent a CVE must be for the EPSS rule, the provisional period |
| `[translation]` | Target language, model provider, model, batch size, per-run limit and request interval |
| `[watchlist]` | The CVSS threshold for stack matches in the digest |
| `[site]` | Language of the site and messages, time zone, site URL |

Run times are the `cron` entries in `.github/workflows/hourly.yml` and `daily.yml`.

## Running locally

Set up the development environment as described in [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) (Traditional Chinese), then run:

```sh
uv run starfault kev                      # read KEV and update the snapshot
uv run starfault cve --backfill-days 3    # read the last 3 days of CVEs
uv run starfault epss                     # read EPSS
GEMINI_API_KEY=<key> uv run starfault translate
uv run starfault site                     # build the site into _site/
```

`push` and `digest` send Telegram messages and need `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID`; `TELEGRAM_THREAD_ID` is optional.

| Exit code | Meaning |
|---|---|
| `0` | Success |
| `1` | A data source or Telegram failed; data already fetched is still saved |
| `2` | Invalid configuration, invalid stack list, invalid `TELEGRAM_THREAD_ID` or `--backfill-days` outside 1 to 90; nothing was done |

## Troubleshooting and known limitations

- **KEV alerts arrive late**: GitHub Actions delays scheduled runs ([GitHub Docs](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule)). For faster alerts, trigger `Hourly` through `workflow_dispatch` from an external cron.
- **Stale-source notice on Today**: CVE or KEV has not updated successfully for over 3 hours, or the EPSS data is more than 2 days old. When a workflow fails, a Telegram group that is set up receives a failure notice.
- **CVE titles stay in English**: in starstrata's use, the Gemini free tier often answered `503` at peak times. Untranslated text is shown as is and retried every day, at most `translation.max_per_run` texts per run.
- **A detail page says "not found"**: the site only lists CVEs that match an alert rule; watched CVEs are kept for 90 days after their last event.
- **Missed stack matches**: a product written in a way your list does not cover is not matched. After going live, check the list against recent CVEs and add the missing spellings to `match`.
- **Duplicate alerts**: alerts are recorded only after Telegram confirms them, so a failed or interrupted send is retried in full. If Telegram accepted the message but the response failed, or a long digest failed after its first part, the retry sends those parts again.

## Data licensing and credits

- CVE records come from the [CVE Program](https://www.cve.org) ([terms of use](https://www.cve.org/Legal/TermsOfUse)) via [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5), including content from CNAs and CISA ADP (Vulnrichment).
- KEV comes from CISA's [Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). KEV due dates are remediation deadlines for US federal agencies; here they are only a reference for urgency.
- EPSS scores come from [FIRST](https://www.first.org/epss/) (Exploit Prediction Scoring System), credited as FIRST requests.

## Development

Design, data formats, rules and tests are in [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) (Traditional Chinese).

## License

[MIT](LICENSE)
