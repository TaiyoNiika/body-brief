# 身体晨报 / Body Brief

A small, dependency-free toolkit plus a bot template that gives your AI assistant a short
morning briefing from **your own** wearable data. Currently supports WHOOP (uses the WHOOP API);
more devices are planned.

> **Uses the WHOOP API.** Not made, endorsed or sponsored by WHOOP. "WHOOP" is a trademark of its owner.
>
> **Not medical advice.** Output is general wellness information only. It is not a diagnosis,
> treatment or a substitute for a doctor. If something feels wrong, talk to a health professional.

## How it works

- **Your own WHOOP app, your own data.** Each user creates their own app in the
  [WHOOP Developer Dashboard](https://developer-dashboard.whoop.com) and authorizes only their own
  account. No shared client, no backend, no server run by anyone else.
- **Data stays on your bot computer.** Files are written to private directories (0700 / 0600) on
  the computer your bot runs on. Nothing is uploaded anywhere by these scripts.
- **Heads-up:** other bots or programs running on the *same computer under the same user* can read
  these files. If that matters to you, run Body Brief on a computer you use only for it.
- Python 3.9+ standard library only. No `pip install`.

## Files

| Path | What it is |
|---|---|
| `whoop/whoop_common.py` | config, private file I/O, token lock, HTTP |
| `whoop/whoop_auth.py` | `url` / `exchange` / `revoke` |
| `whoop/whoop_fetch.py` | daily pull → `YYYY-MM-DD.json` + `latest.json`, then retention pruning |
| `tests/` | offline unit tests (fake data, fictional dates) |
| `callback/index.html` | optional static callback page: no JS, no analytics, no-referrer, strict CSP |
| `PRIVACY_POLICY_TEMPLATE.md` | fill in and host; WHOOP asks for a privacy policy URL |
| `template/` | text drafts of the bot template (profile, skills, routines) |
| `tools/gen_manifest.py` | writes `MANIFEST.sha256` and pastes it into the install skill |
| `tools/clean_check.py` | pre-release check for personal data and secret-like strings |
| `livetest/` | optional manual test of PKCE / response_mode against your own app |

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `WHOOP_CLIENT_ID`, `WHOOP_CLIENT_SECRET`, `WHOOP_REDIRECT_URI` | — | or put them in the credentials file |
| `WHOOP_CREDENTIALS_FILE` | `~/.secrets/whoop/client.json` | JSON with `client_id`, `client_secret`, `redirect_uri`; **must be 0600** |
| `WHOOP_SECRETS_DIR` | `~/.secrets/whoop` | token + OAuth state |
| `WHOOP_OUTPUT_DIR` | `~/health/whoop` | daily JSON |
| `WHOOP_TZ` | `$TZ`, else system zone | IANA name, e.g. `Europe/Berlin` |
| `WHOOP_RETENTION_DAYS` | `30` | delete `YYYY-MM-DD.json` older than N days; `0` keeps everything. `latest.json` and tokens are never pruned |
| `WHOOP_PKCE` | off | `1` adds an S256 PKCE challenge (same as `--pkce`) |

## Setup

1. Create an app in the WHOOP Developer Dashboard. Scopes: `read:recovery read:sleep read:cycles read:workout` (plus `offline`).
   Redirect URI: an `https://` page you control (for example your own copy of `callback/index.html`).
   New apps start on WHOOP's Sandbox tier (up to 10 members), which is plenty for one person.
2. Store credentials (never paste them into chat in plain text; use your bot's secure form):
   `~/.secrets/whoop/client.json`, then `chmod 600` it.
3. `python3 whoop/whoop_auth.py url [--pkce] [--response-mode fragment]` → open the HTML file it
   prints, approve, copy the whole address bar.
4. `python3 whoop/whoop_auth.py exchange` → paste the URL (input hidden).
5. `python3 whoop/whoop_fetch.py` once a day (your bot's routine does this).

Exit codes of `whoop_fetch.py`: 0 scored, 1 not scored yet, 2 config error, 3 re-authorize, 4 API error.

## Disconnect / delete

```
python3 whoop/whoop_auth.py revoke                 # disconnect at WHOOP + delete local token
python3 whoop/whoop_auth.py revoke --delete-data   # ...and delete the JSON files too
python3 whoop/whoop_auth.py revoke --token-only    # revoke only the stored refresh token
python3 whoop/whoop_auth.py revoke --local-only    # delete local files, no network
```

## About the callback page

The code in the redirect is single-use, expires within minutes and cannot be exchanged without
your client secret. Still, a normal `?code=` redirect reaches the web server hosting the page (and
its logs). Live test (2026-10): WHOOP does **not** honour `response_mode=fragment` — the code still
comes back after `?`, so treat the callback page's host as able to see it. Fragment mode stays off by
default; the option remains only for providers that support it. WHOOP also does **not** enforce PKCE
(a code was accepted without `code_verifier`). Keep `--pkce` on as defence in depth, but the real
protection is your client secret staying private plus the `state` check. Re-run `livetest/` to recheck.

## Tests

```
python3 -m unittest discover -s tests -v
```

---

## 中文简介

身体晨报 / Body Brief：可穿戴设备数据晨报，用**你自己的**设备数据给你的 AI 助手生成晨间简报。目前支持 WHOOP（使用 WHOOP API），后续支持更多设备。

- **使用 WHOOP API**，与 WHOOP 公司无关联、未获其认可。
- **不是医疗建议**，只提供一般健康信息；身体不适请咨询医生。
- 每个用户自建 WHOOP App、只授权自己的账号；没有共享密钥，没有任何第三方服务器。
- 数据只保存在你自己的机器人电脑上的私有目录（0700/0600）。
- **提醒：同一台电脑上、同一用户下运行的其他机器人或程序也能读到这些文件。**
- 按日期命名的文件默认保留 30 天（`WHOOP_RETENTION_DAYS`，设 0 关闭）；`latest.json` 和 token 不会被删。
- 只用 Python 标准库。
