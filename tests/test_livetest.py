"""Offline tests for livetest/ (fake HTTP; fictional values only)."""
import contextlib
import io
import json
import os
import stat
import sys
import tempfile
import unittest
import urllib.parse
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "whoop"))
sys.path.insert(0, os.path.join(ROOT, "livetest"))
import whoop_common as wc  # noqa: E402
import pkce_prepare  # noqa: E402
import pkce_judge  # noqa: E402

REDIRECT = "https://example.com/whoop/callback"


class FakeHttp:
    def __init__(self, token_results):
        self.token_results = list(token_results)  # each: dict (success) or HttpError
        self.calls = []

    def __call__(self, method, url, data=None, headers=None, timeout=30):
        self.calls.append((method, url, dict(data or {})))
        if url == wc.TOKEN_URL:
            r = self.token_results.pop(0)
            if isinstance(r, Exception):
                raise r
            return r
        if url == wc.REVOKE_URL:
            return None
        raise AssertionError("unexpected call " + method + " " + url)


OK = {"access_token": "FAKE-AT", "refresh_token": "FAKE-RT", "expires_in": 3600, "scope": "offline"}


class TestLiveTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        home = self.tmp.name
        self.env = mock.patch.dict(os.environ, {
            "HOME": home, "WHOOP_SECRETS_DIR": os.path.join(home, "live"),
            "PKCE_TEST_DIR": os.path.join(home, "pkce"),
            "WHOOP_CLIENT_ID": "FAKE-CID", "WHOOP_CLIENT_SECRET": "FAKE-CSECRET",
            "WHOOP_REDIRECT_URI": REDIRECT}, clear=False)
        self.env.start()
        for k in ("WHOOP_TEST_CLIENT_ID", "WHOOP_TEST_CLIENT_SECRET", "PKCE_A_MODE", "PKCE_TEST_URL"):
            os.environ.pop(k, None)
        self.out = io.StringIO()
        with contextlib.redirect_stdout(self.out):
            pkce_prepare.main()
        self.dir = os.environ["PKCE_TEST_DIR"]
        self.flows = json.load(open(os.path.join(self.dir, "flows.json")))

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def redirect(self, flow, sep):
        st = self.flows["flows"][flow]["state"]
        return REDIRECT + sep + urllib.parse.urlencode({"code": "FAKE-CODE-" + flow, "state": st})

    def run_judge(self, flow, url, http):
        with contextlib.redirect_stdout(io.StringIO()) as o:
            rc = pkce_judge.judge(flow, http=http, pasted=url)
        return rc, o.getvalue()

    def test_prepare_files_private_and_nothing_secret_printed(self):
        self.assertEqual(stat.S_IMODE(os.stat(self.dir).st_mode), 0o700)
        for f in ("flows.json", "links.html"):
            self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.dir, f)).st_mode), 0o600)
        printed = self.out.getvalue()
        for s in ("FAKE-CID", "example.com", self.flows["flows"]["A"]["code_verifier"], "code_challenge"):
            self.assertNotIn(s, printed)
        html = open(os.path.join(self.dir, "links.html")).read()
        import html as htmlmod
        import re
        hrefs = [htmlmod.unescape(h) for h in re.findall(r'href="([^"]+)"', html)]
        self.assertEqual(len(hrefs), 2)
        qs = [urllib.parse.parse_qs(urllib.parse.urlsplit(h).query) for h in hrefs]
        self.assertTrue(all(q["code_challenge_method"] == ["S256"] for q in qs))
        self.assertEqual([q.get("response_mode") for q in qs], [["fragment"], None])

    def test_refuses_live_secrets_dir(self):
        os.environ["PKCE_TEST_DIR"] = os.environ["WHOOP_SECRETS_DIR"]
        with self.assertRaises(SystemExit):
            pkce_prepare.test_dir()

    def test_enforced_scenario(self):
        http = FakeHttp([wc.HttpError(400, error="invalid_grant"), wc.HttpError(400, error="invalid_grant"), OK])
        rc, out = self.run_judge("A", self.redirect("A", "#"), http)
        self.assertEqual(rc, 0)
        a = json.load(open(os.path.join(self.dir, "result_A.json")))
        self.assertEqual(a["code_location"], "fragment")
        self.assertNotIn("code_verifier", http.calls[0][2])
        self.assertIn("code_verifier", http.calls[1][2])
        rc, out = self.run_judge("B", self.redirect("B", "?"), http)
        b = json.load(open(os.path.join(self.dir, "result_B.json")))
        self.assertEqual(b["code_location"], "query")
        self.assertTrue(b["attempt1"]["accepted"])
        self.assertEqual(b["attempt1"]["revoked"], "ok")
        self.assertFalse(os.path.exists(os.path.join(self.dir, "token_B.json")))
        revokes = [c for c in http.calls if c[1] == wc.REVOKE_URL]
        self.assertEqual(revokes[0][2]["token"], "FAKE-RT")
        self.assertFalse(any(c[0] == "DELETE" for c in http.calls))
        self.assertNotIn("FAKE-RT", out + json.dumps(b))
        text = "\n".join(pkce_judge.conclude(a, b))
        self.assertIn("PKCE enforced", text)
        self.assertIn("probably yes", text)

    def test_not_enforced_scenario(self):
        http = FakeHttp([OK])
        self.run_judge("A", self.redirect("A", "?"), http)
        a = json.load(open(os.path.join(self.dir, "result_A.json")))
        self.assertEqual(a["code_location"], "query")
        self.assertIn("skipped", a["attempt2"])
        text = "\n".join(pkce_judge.conclude(a, None))
        self.assertIn("PKCE NOT enforced", text)
        self.assertIn("NO (code arrived in query)", text)

    def test_wrong_verifier_mode_and_single_use_flow(self):
        os.environ["PKCE_A_MODE"] = "wrong"
        http = FakeHttp([wc.HttpError(400, error="invalid_grant"), OK])
        self.run_judge("A", self.redirect("A", "#"), http)
        sent = http.calls[0][2]["code_verifier"]
        self.assertNotEqual(sent, self.flows["flows"]["A"]["code_verifier"])
        with self.assertRaises(SystemExit):
            self.run_judge("A", self.redirect("A", "#"), http)

    def test_bad_state_spends_nothing(self):
        http = FakeHttp([])
        url = REDIRECT + "?code=FAKE-CODE&state=WRONGxxx"
        rc, _ = self.run_judge("B", url, http)
        self.assertEqual(rc, 2)
        self.assertEqual(http.calls, [])

    def test_cleanup(self):
        with contextlib.redirect_stdout(io.StringIO()):
            pkce_judge.main(["x", "cleanup"])
        self.assertFalse(os.path.exists(self.dir))


if __name__ == "__main__":
    unittest.main()
