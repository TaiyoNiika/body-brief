#!/usr/bin/env python3
"""WHOOP OAuth 2.0 for Body Brief (your own WHOOP app, your own data).

  python3 whoop_auth.py url [--pkce] [--response-mode query|fragment]
  (Live-tested: WHOOP ignores response_mode=fragment and does not enforce PKCE; default stays query.)
        Writes the authorization link to <secrets>/auth_link.html (0600) and prints only that path.
  python3 whoop_auth.py exchange
        Reads the full address-bar URL you were sent back to from $WHOOP_AUTH_REDIRECT_URL,
        or from stdin (hidden) if that is unset. Checks state, then saves the token.
  python3 whoop_auth.py revoke [--token-only | --local-only] [--delete-data]
        Default: disconnect this app from your WHOOP account (DELETE /v2/user/access),
        then delete the local token. --token-only revokes just the stored refresh token.
        --local-only deletes local files without calling WHOOP. --delete-data also removes
        the JSON files in the output directory.

Credentials come from env vars or the 0600 credentials file (see whoop_common).
Nothing secret (client secret, codes, tokens, the redirect host) is printed or logged.
Exit codes: 0 ok, 2 config/validation error, 3 WHOOP rejected the request, 4 no refresh token.
"""
import base64
import getpass
import glob
import hashlib
import hmac
import html
import json
import os
import secrets
import string
import sys
import time
import urllib.parse

import whoop_common as wc

STATE_TTL = 15 * 60


def make_state():
    # WHOOP docs: a self-generated state "must be eight characters long".
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(8))


def make_pkce():
    """RFC 7636 S256 pair: (verifier, challenge)."""
    verifier = secrets.token_urlsafe(64)[:96]
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def pkce_challenge(verifier):
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


def build_auth_url(client_id, redirect_uri, state, code_challenge=None, response_mode=None):
    q = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": wc.SCOPES,
        "state": state,
    }
    if code_challenge:
        q["code_challenge"] = code_challenge
        q["code_challenge_method"] = "S256"
    if response_mode:
        q["response_mode"] = response_mode
    return wc.AUTH_URL + "?" + urllib.parse.urlencode(q, quote_via=urllib.parse.quote)


def write_link_html(path, links):
    """links: list of (label, url). Written 0600; the URLs are never printed."""
    items = "\n".join(
        f'<li><p>{html.escape(label)}</p><p><a href="{html.escape(url, quote=True)}" '
        f'rel="noreferrer noopener">{html.escape(label)}</a></p></li>' for label, url in links)
    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="referrer" content="no-referrer">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>WHOOP authorization link</title>
<style>body{{font-family:system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem;line-height:1.5}}</style>
</head><body>
<h1>WHOOP authorization</h1>
<p>Open a link, sign in to WHOOP and approve. You will land on your callback page.
Copy the <strong>whole address bar</strong> (including anything after <code>#</code>) and paste it back to your bot.
Each link works once and only for a short time.</p>
<ol>
{items}
</ol>
</body></html>
"""
    d = os.path.dirname(path)
    wc.ensure_dir(d)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(doc)
    os.chmod(path, 0o600)
    return path


def _check_redirect_scheme(redirect_uri):
    if not redirect_uri.startswith(("https://", "whoop://")):
        wc.log("warning: WHOOP requires the redirect URI to start with https:// or whoop://")


def cmd_url(pkce=False, response_mode=None):
    creds = wc.load_credentials(need_secret=False, need_redirect=True)
    _check_redirect_scheme(creds["redirect_uri"])
    state = make_state()
    saved = {"state": state, "created_at": int(time.time()), "redirect_uri": creds["redirect_uri"],
             "response_mode": response_mode or "query"}
    challenge = None
    if pkce:
        saved["code_verifier"], challenge = make_pkce()
    wc.atomic_write_json(wc.state_path(), saved)
    url = build_auth_url(creds["client_id"], creds["redirect_uri"], state, challenge, response_mode)
    path = write_link_html(os.path.join(wc.secrets_dir(), "auth_link.html"), [("Authorize with WHOOP", url)])
    print(path)
    return 0


def split_redirect(redirect_url):
    """Return (params, location) where location is 'query', 'fragment' or None.

    Accepts both the normal ?code=... form and the response_mode=fragment #code=... form.
    Refuses a URL that carries OAuth parameters in both places.
    """
    p = urllib.parse.urlsplit(redirect_url.strip())
    q = urllib.parse.parse_qs(p.query)
    f = urllib.parse.parse_qs(p.fragment)
    keys = ("code", "error", "state")
    in_q, in_f = any(k in q for k in keys), any(k in f for k in keys)
    if in_q and in_f:
        raise ValueError("OAuth parameters found in both ?query and #fragment; refusing")
    if in_f:
        return f, "fragment"
    if in_q:
        return q, "query"
    return {}, None


def parse_redirect(redirect_url, saved, now=None, ttl=STATE_TTL):
    """Validate the pasted redirect URL against the saved state. Returns (code, location)."""
    now = now or time.time()
    params, location = split_redirect(redirect_url)
    if "error" in params:
        raise ValueError("WHOOP returned an authorization error: " + params["error"][0][:40])
    p = urllib.parse.urlsplit(redirect_url.strip())
    exp = urllib.parse.urlsplit(saved["redirect_uri"])
    if (p.scheme, p.netloc.lower(), p.path) != (exp.scheme, exp.netloc.lower(), exp.path):
        raise ValueError("the pasted URL does not match the registered redirect URI")
    got_state = (params.get("state") or [""])[0]
    if not got_state or not hmac.compare_digest(got_state, saved["state"]):
        raise ValueError("state mismatch")
    if now - saved["created_at"] > ttl:
        raise ValueError("authorization link expired; generate a new one")
    code = (params.get("code") or [""])[0]
    if not code:
        raise ValueError("no authorization code in the pasted URL")
    return code, location


def token_form(code, saved, creds, include_verifier=True):
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": saved["redirect_uri"],
        "client_id": creds["client_id"],
        "client_secret": creds["client_secret"],
    }
    if include_verifier and saved.get("code_verifier"):
        form["code_verifier"] = saved["code_verifier"]
    return form


def _read_pasted_url():
    v = os.environ.get("WHOOP_AUTH_REDIRECT_URL", "").strip()
    if v:
        return v
    if sys.stdin.isatty():
        return getpass.getpass("Paste the full address-bar URL (input hidden): ").strip()
    return sys.stdin.readline().strip()


def cmd_exchange(http=wc.http_request, pasted=None):
    creds = wc.load_credentials(need_secret=True)
    try:
        with open(wc.state_path(), encoding="utf-8") as f:
            saved = json.load(f)
    except FileNotFoundError:
        wc.log("no saved state; run the `url` command first")
        return 2
    try:
        code, location = parse_redirect(pasted if pasted is not None else _read_pasted_url(), saved)
    except ValueError as e:
        wc.log(f"validation failed: {e}")
        return 2
    with wc.token_lock():
        try:
            resp = wc.post_token(token_form(code, saved, creds), http=http)
        except wc.HttpError as e:
            wc.log(f"token exchange failed ({e})")
            return 3
        if not resp or not resp.get("access_token"):
            wc.log("token exchange failed (response missing fields)")
            return 3
        tok = wc.save_token(resp)
    os.unlink(wc.state_path())  # state is single-use
    if not tok.get("refresh_token"):
        wc.log("warning: no refresh token returned (is the offline scope missing?)")
        return 4
    wc.log(f"authorized; token saved (code arrived in the {location})")
    return 0


def _remove(path):
    try:
        os.unlink(path)
        return True
    except FileNotFoundError:
        return False


def delete_local(delete_data=False):
    removed = sum(_remove(p) for p in (wc.token_path(), wc.state_path(),
                                       os.path.join(wc.secrets_dir(), "auth_link.html")))
    if delete_data:
        out = wc.output_dir()
        for p in glob.glob(os.path.join(out, "*.json")):
            removed += _remove(p)
    return removed


def cmd_revoke(mode="full", delete_data=False, http=wc.http_request):
    if mode != "local":
        try:
            tok = wc.load_token()
        except (FileNotFoundError, ValueError):
            tok = None
        if not tok:
            wc.log("no local token; nothing to revoke at WHOOP (use --local-only to just clean up)")
        else:
            try:
                if mode == "token":
                    creds = wc.load_credentials(need_secret=True)
                    http("POST", wc.REVOKE_URL, data={
                        "token": tok.get("refresh_token") or tok["access_token"],
                        "token_type_hint": "refresh_token" if tok.get("refresh_token") else "access_token",
                        "client_id": creds["client_id"],
                        "client_secret": creds["client_secret"],
                    })
                else:
                    if tok.get("expires_at", 0) <= time.time() + 60:
                        import whoop_fetch  # refresh first so the DELETE is authorized
                        tok = whoop_fetch.refresh(http=http)
                    http("DELETE", wc.API_BASE + "/v2/user/access",
                         headers={"Authorization": "Bearer " + tok["access_token"]})
            except Exception as e:  # report status only
                wc.log(f"revoke at WHOOP failed ({type(e).__name__}: {e}); local files kept")
                return 3
            wc.log("access revoked at WHOOP")
    n = delete_local(delete_data)
    wc.log(f"removed {n} local file(s)")
    return 0


def main(argv):
    args = argv[1:]
    if not args or args[0] not in ("url", "exchange", "revoke"):
        print(__doc__, file=sys.stderr)
        return 2
    cmd, opts = args[0], args[1:]
    try:
        if cmd == "url":
            mode = None
            if "--response-mode" in opts:
                i = opts.index("--response-mode")
                mode = opts[i + 1] if i + 1 < len(opts) else ""
                if mode not in ("query", "fragment"):
                    print("--response-mode must be query or fragment", file=sys.stderr)
                    return 2
            pkce = "--pkce" in opts or os.environ.get("WHOOP_PKCE", "") == "1"
            return cmd_url(pkce=pkce, response_mode=mode)
        if cmd == "exchange":
            return cmd_exchange()
        mode = "token" if "--token-only" in opts else "local" if "--local-only" in opts else "full"
        return cmd_revoke(mode, delete_data="--delete-data" in opts)
    except wc.ConfigError as e:
        wc.log(f"config error: {e}")
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
