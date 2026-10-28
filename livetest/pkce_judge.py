#!/usr/bin/env python3
"""Judge one live PKCE test flow from the address-bar URL you were redirected to.

  python3 pkce_judge.py A      # paste the URL from link A (input hidden)
  python3 pkce_judge.py B      # paste the URL from link B
  python3 pkce_judge.py report # print the combined conclusion
  python3 pkce_judge.py cleanup  # delete the whole test directory

Flow A (authorization codes are single-use, so each flow gets its own code):
  1. exchange WITHOUT code_verifier (or with a wrong one: PKCE_A_MODE=wrong)  -> expect rejection
  2. exchange the same code WITH the right verifier -> tells whether a failed attempt burns the code
Flow B (positive control):
  1. exchange WITH the right verifier -> expect success

Every token obtained is saved only in the test directory (0600), revoked right away via the OAuth
revocation endpoint (that token only - NOT DELETE /v2/user/access, which would disconnect the whole
app) and then deleted. No data API is called. Printed: only where the code arrived (? or #), HTTP
status and OAuth error codes. Never the URL, code, verifier, tokens, client secret or redirect host.

Env: WHOOP_TEST_CLIENT_ID/WHOOP_TEST_CLIENT_SECRET (if prepare used the test app) or
WHOOP_CLIENT_ID/WHOOP_CLIENT_SECRET; PKCE_TEST_URL may hold the pasted URL instead of stdin.
"""
import getpass
import json
import os
import shutil
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "whoop"))
sys.path.insert(0, HERE)
import whoop_auth  # noqa: E402
import whoop_common as wc  # noqa: E402
from pkce_prepare import test_dir  # noqa: E402


def creds(source):
    pre = "WHOOP_TEST_" if source == "test-app" else "WHOOP_"
    cid = os.environ.get(pre + "CLIENT_ID", "").strip()
    sec = os.environ.get(pre + "CLIENT_SECRET", "").strip()
    if not cid or not sec:
        raise SystemExit(f"missing {pre}CLIENT_ID / {pre}CLIENT_SECRET")
    return {"client_id": cid, "client_secret": sec}


def read_url():
    v = os.environ.get("PKCE_TEST_URL", "").strip()
    if v:
        return v
    if sys.stdin.isatty():
        return getpass.getpass("Paste the full address-bar URL (input hidden): ").strip()
    return sys.stdin.readline().strip()


def attempt(code, flow, saved, c, verifier, http):
    form = {"grant_type": "authorization_code", "code": code, "redirect_uri": saved["redirect_uri"],
            "client_id": c["client_id"], "client_secret": c["client_secret"]}
    if verifier is not None:
        form["code_verifier"] = verifier
    try:
        resp = http("POST", wc.TOKEN_URL, data=form)
    except wc.HttpError as e:
        return {"status": e.status, "error": e.error, "accepted": False}
    except OSError as e:
        return {"status": None, "error": "network:" + type(e).__name__, "accepted": False}
    ok = bool(resp and resp.get("access_token"))
    out = {"status": 200, "error": None, "accepted": ok}
    if ok:
        out.update(dispose(resp, flow, c, http))
    return out


def dispose(resp, flow, c, http):
    """Store briefly (0600, test dir), revoke that token only, then delete."""
    d = test_dir()
    path = os.path.join(d, f"token_{flow}.json")
    wc.atomic_write_json(path, {k: resp.get(k) for k in ("access_token", "refresh_token", "expires_in", "scope")})
    tok = resp.get("refresh_token") or resp.get("access_token")
    hint = "refresh_token" if resp.get("refresh_token") else "access_token"
    try:
        http("POST", wc.REVOKE_URL, data={"token": tok, "token_type_hint": hint,
                                          "client_id": c["client_id"], "client_secret": c["client_secret"]})
        revoked = "ok"
    except (wc.HttpError, OSError) as e:
        revoked = f"failed ({type(e).__name__}: {getattr(e, 'status', '')})"
    os.unlink(path)
    return {"got_refresh_token": bool(resp.get("refresh_token")), "revoked": revoked, "token_file_deleted": True}


def judge(flow, http=wc.http_request, pasted=None):
    d = test_dir()
    fpath = os.path.join(d, "flows.json")
    with open(fpath, encoding="utf-8") as f:
        data = json.load(f)
    fl = data["flows"][flow]
    if fl.get("used"):
        raise SystemExit(f"flow {flow} was already judged; run pkce_prepare.py again for fresh links")
    url = pasted if pasted is not None else read_url()
    _, location = whoop_auth.split_redirect(url)
    saved = {"state": fl["state"], "created_at": data["created_at"], "redirect_uri": data["redirect_uri"]}
    try:
        code, location = whoop_auth.parse_redirect(url, saved, ttl=data["ttl_s"])
    except ValueError as e:
        print(f"flow {flow}: code location = {location or 'none'}; validation failed: {e}")
        return 2
    fl["used"] = True
    wc.atomic_write_json(fpath, data)  # mark before spending the code
    c = creds(data["client"])
    res = {"flow": flow, "requested_response_mode": fl["response_mode"], "code_location": location,
           "judged_at": int(time.time())}
    if flow == "A":
        wrong = os.environ.get("PKCE_A_MODE", "missing") == "wrong"
        bad = (whoop_auth.make_pkce()[0]) if wrong else None
        res["attempt1_mode"] = "wrong_verifier" if wrong else "no_verifier"
        res["attempt1"] = attempt(code, flow, saved, c, bad, http)
        if res["attempt1"]["accepted"]:
            res["attempt2"] = {"skipped": "code already used by attempt 1"}
        else:
            res["attempt2"] = attempt(code, flow, saved, c, fl["code_verifier"], http)
    else:
        res["attempt1_mode"] = "correct_verifier"
        res["attempt1"] = attempt(code, flow, saved, c, fl["code_verifier"], http)
    wc.atomic_write_json(os.path.join(d, f"result_{flow}.json"), res)
    print(json.dumps(res, indent=2))
    return 0


def conclude(a, b):
    lines = []
    if a:
        lines.append(f"response_mode=fragment honoured: {'yes' if a['code_location'] == 'fragment' else 'NO (code arrived in ' + str(a['code_location']) + ')'}")
    if b:
        lines.append(f"query flow code location: {b['code_location']}")
    if b and not b["attempt1"]["accepted"]:
        lines.append("INCONCLUSIVE: B with the correct verifier was rejected "
                     f"(status {b['attempt1']['status']}, {b['attempt1']['error']}); check app/redirect setup")
    if a:
        a1 = a["attempt1"]
        if a1["accepted"]:
            lines.append(f"PKCE NOT enforced: A attempt 1 ({a['attempt1_mode']}) was accepted")
        elif b and b["attempt1"]["accepted"]:
            lines.append(f"PKCE enforced: A attempt 1 ({a['attempt1_mode']}) rejected "
                         f"(status {a1['status']}, {a1['error']}) while B with the correct verifier succeeded")
        a2 = a.get("attempt2") or {}
        if "accepted" in a2:
            lines.append("failed PKCE attempt burns the code: " + ("no (attempt 2 succeeded)" if a2["accepted"]
                         else f"probably yes (attempt 2 status {a2['status']}, {a2['error']})"))
    return lines


def main(argv):
    if len(argv) != 2 or argv[1] not in ("A", "B", "report", "cleanup"):
        print(__doc__, file=sys.stderr)
        return 2
    d = test_dir()
    if argv[1] == "cleanup":
        if os.path.isdir(d):
            shutil.rmtree(d)
        print("test directory removed")
        return 0
    if argv[1] == "report":
        res = {}
        for f in ("A", "B"):
            p = os.path.join(d, f"result_{f}.json")
            if os.path.exists(p):
                with open(p, encoding="utf-8") as fh:
                    res[f] = json.load(fh)
        for line in conclude(res.get("A"), res.get("B")) or ["no results yet"]:
            print("-", line)
        return 0
    return judge(argv[1])


if __name__ == "__main__":
    sys.exit(main(sys.argv))
