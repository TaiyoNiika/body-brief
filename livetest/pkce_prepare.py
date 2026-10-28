#!/usr/bin/env python3
"""Prepare a manual live test of PKCE and response_mode against your own WHOOP app.

Makes no network calls. Creates a separate 0700 test directory (never the normal secrets dir),
writes two flows (state + PKCE verifier each) to flows.json (0600) and both authorization links to
links.html (0600). Prints only file paths - never the links, client id, redirect or verifier.

  Link A: PKCE (S256) + response_mode=fragment
  Link B: PKCE (S256) + normal query response

Env: WHOOP_TEST_CLIENT_ID (preferred: a separate test app) or WHOOP_CLIENT_ID, and
WHOOP_REDIRECT_URI (must be registered on that app). PKCE_TEST_DIR overrides the test directory
(default ~/.secrets/whoop-pkce-test). PKCE_TEST_TTL_HOURS (default 6).
"""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "whoop"))
import whoop_auth  # noqa: E402
import whoop_common as wc  # noqa: E402


def test_dir():
    d = os.environ.get("PKCE_TEST_DIR") or os.path.join(os.path.expanduser("~"), ".secrets", "whoop-pkce-test")
    d = os.path.realpath(d)
    live = {os.path.realpath(wc.secrets_dir()),
            os.path.realpath(os.path.join(os.path.expanduser("~"), ".secrets", "whoop"))}
    if d in live:
        raise SystemExit("refusing: PKCE_TEST_DIR must not be the normal WHOOP secrets directory")
    return d


def client_id():
    if os.environ.get("WHOOP_TEST_CLIENT_ID", "").strip():
        return os.environ["WHOOP_TEST_CLIENT_ID"].strip(), "test-app"
    if os.environ.get("WHOOP_CLIENT_ID", "").strip():
        return os.environ["WHOOP_CLIENT_ID"].strip(), "main-app"
    raise SystemExit("missing WHOOP_TEST_CLIENT_ID / WHOOP_CLIENT_ID")


def main():
    d = test_dir()
    redirect = os.environ.get("WHOOP_REDIRECT_URI", "").strip()
    if not redirect:
        raise SystemExit("missing WHOOP_REDIRECT_URI")
    cid, source = client_id()
    flows, links = {}, []
    for name, mode in (("A", "fragment"), ("B", None)):
        state = whoop_auth.make_state()
        verifier, challenge = whoop_auth.make_pkce()
        flows[name] = {"state": state, "code_verifier": verifier, "response_mode": mode or "query",
                       "used": False}
        url = whoop_auth.build_auth_url(cid, redirect, state, challenge, mode)
        label = ("A — PKCE + response_mode=fragment (do this first)" if name == "A"
                 else "B — PKCE + normal query (do this second)")
        links.append((label, url))
    wc.ensure_dir(d)
    wc.atomic_write_json(os.path.join(d, "flows.json"), {
        "created_at": int(time.time()),
        "ttl_s": int(float(os.environ.get("PKCE_TEST_TTL_HOURS", "6")) * 3600),
        "redirect_uri": redirect,
        "client": source,
        "flows": flows,
    })
    html_path = whoop_auth.write_link_html(os.path.join(d, "links.html"), links)
    print(f"test dir: {d}")
    print(f"links:    {html_path}  (2 links, mode 0600)")
    print(f"client:   {source}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
