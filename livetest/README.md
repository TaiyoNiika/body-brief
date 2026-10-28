# Live PKCE test (manual, optional)

Checks two things against **your own** WHOOP app before you enable `--pkce` / `response_mode`:

1. Does WHOOP honour `response_mode=fragment` (code after `#`) and the normal query (`?`)?
2. Is PKCE really enforced (a code from a PKCE link is rejected without the right `code_verifier`)?

Nothing here runs automatically and nothing touches your normal token in `~/.secrets/whoop`.

## Safety

- Uses a separate directory `~/.secrets/whoop-pkce-test` (0700); refuses to use the normal secrets dir.
- Prefer a **separate test app** (`WHOOP_TEST_CLIENT_ID` / `WHOOP_TEST_CLIENT_SECRET`) with the same
  redirect URI registered. Re-authorizing the *same* app may replace or affect its existing grant.
- Every token obtained is revoked with the OAuth revocation endpoint (that token only) and deleted.
  The test never calls `DELETE /v2/user/access`, which would disconnect the whole app for you.
- Prints only where the code arrived, HTTP status and OAuth error codes.

## Steps

```bash
python3 livetest/pkce_prepare.py          # no network; writes links.html (0600), prints its path
# open links.html in your browser, click link A, approve, copy the address bar
python3 livetest/pkce_judge.py A          # paste (hidden); do this within a few minutes
# then link B
python3 livetest/pkce_judge.py B
python3 livetest/pkce_judge.py report     # conclusion
python3 livetest/pkce_judge.py cleanup    # delete the test directory
```

Authorization codes are single-use and short-lived, so each flow has its own link and code.
Flow A first tries without the verifier (expect rejection), then with it (shows whether a failed
attempt burns the code). Flow B is the positive control (correct verifier, expect success).
`PKCE_A_MODE=wrong` makes A's first attempt use a wrong verifier instead of none.
