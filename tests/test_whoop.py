"""Offline tests with fake WHOOP responses. No network, no real secrets."""
import contextlib
import io
import json
import os
import stat
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "whoop"))
import whoop_common as wc  # noqa: E402
import whoop_auth  # noqa: E402
import whoop_fetch  # noqa: E402

FAKE_ACCESS_OLD = "FAKE-ACCESS-OLD-aaaa"
FAKE_REFRESH_OLD = "FAKE-REFRESH-OLD-bbbb"
FAKE_ACCESS_NEW = "FAKE-ACCESS-NEW-cccc"
FAKE_REFRESH_NEW = "FAKE-REFRESH-NEW-dddd"
FAKE_SECRET = "FAKE-CLIENT-SECRET-eeee"  # pragma: allowlist secret  (fake test value)
TEST_TZ = "Asia/Tokyo"  # fixed UTC+9, no DST; any IANA zone works
SENSITIVE = [FAKE_ACCESS_OLD, FAKE_REFRESH_OLD, FAKE_ACCESS_NEW, FAKE_REFRESH_NEW, FAKE_SECRET]

RECOVERY = {"records": [
    {"cycle_id": 3, "sleep_id": "s-pending", "score_state": "PENDING_SCORE"},
    {"cycle_id": 2, "sleep_id": "s-main", "score_state": "SCORED",
     "score": {"user_calibrating": False, "recovery_score": 67, "resting_heart_rate": 52,
               "hrv_rmssd_milli": 61.234, "spo2_percentage": 96.5, "skin_temp_celsius": 33.9}}]}
SLEEP_MAIN = {"id": "s-main", "cycle_id": 2, "nap": False, "score_state": "SCORED",
              "start": "2031-03-13T15:30:00.000Z", "end": "2031-03-13T23:15:00.000Z",
              "score": {"stage_summary": {"total_in_bed_time_milli": 27_900_000,
                                          "total_awake_time_milli": 1_800_000,
                                          "total_no_data_time_milli": 0,
                                          "total_light_sleep_time_milli": 12_600_000,
                                          "total_slow_wave_sleep_time_milli": 6_300_000,
                                          "total_rem_sleep_time_milli": 7_200_000,
                                          "sleep_cycle_count": 4, "disturbance_count": 9},
                        "respiratory_rate": 15.2, "sleep_performance_percentage": 91,
                        "sleep_consistency_percentage": 80, "sleep_efficiency_percentage": 93.5}}
CYCLES = {"records": [
    {"id": 3, "start": "2031-03-14T23:00:00.000Z", "score_state": "PENDING_SCORE"},
    {"id": 2, "start": "2031-03-13T15:30:00.000Z", "score_state": "SCORED",
     "score": {"strain": 4.1, "kilojoule": 3000}},
    {"id": 1, "start": "2031-03-12T15:00:00.000Z", "end": "2031-03-13T15:30:00.000Z",
     "score_state": "SCORED", "score": {"strain": 13.7, "kilojoule": 9100}}]}
WORKOUTS = {"records": [
    {"id": "w2", "sport_name": "running", "score_state": "SCORED",
     "start": "2031-03-14T00:30:00.000Z", "end": "2031-03-14T01:10:00.000Z", "score": {"strain": 9.0}},
    {"id": "w1", "sport_name": "weightlifting", "score_state": "SCORED",
     "start": "2031-03-13T10:00:00.000Z", "end": "2031-03-13T11:00:00.000Z",
     "score": {"strain": 8.2, "average_heart_rate": 120, "max_heart_rate": 160, "kilojoule": 1500}}]}


def local(utc_iso):
    from zoneinfo import ZoneInfo
    return wc.parse_ts(utc_iso).astimezone(ZoneInfo(TEST_TZ)).isoformat(timespec="seconds")


class FakeHttp:
    def __init__(self, refresh_status=None, routes=None):
        self.calls = []
        self.refresh_status = refresh_status
        self.routes = routes or {}

    def __call__(self, method, url, data=None, headers=None, timeout=30):
        self.calls.append((method, url, dict(data or {}), dict(headers or {})))
        if url == wc.REVOKE_URL or (method == "DELETE" and url.endswith("/v2/user/access")):
            return None
        if url == wc.TOKEN_URL:
            if self.refresh_status:
                raise wc.HttpError(self.refresh_status)
            if data["grant_type"] == "authorization_code":
                return {"access_token": FAKE_ACCESS_OLD, "refresh_token": FAKE_REFRESH_OLD,
                        "expires_in": 3600, "scope": "offline read:recovery", "token_type": "bearer"}
            assert data["refresh_token"] == FAKE_REFRESH_OLD
            return {"access_token": FAKE_ACCESS_NEW, "refresh_token": FAKE_REFRESH_NEW,
                    "expires_in": 3600, "scope": "offline read:recovery", "token_type": "bearer"}
        path = url[len(wc.API_BASE):].split("?")[0]
        r = self.routes.get(path)
        if isinstance(r, Exception):
            raise r
        if r is None:
            raise wc.HttpError(404)
        return r


ROUTES = {"/v2/recovery": RECOVERY, "/v2/activity/sleep/s-main": SLEEP_MAIN,
          "/v2/cycle": CYCLES, "/v2/activity/workout": WORKOUTS}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.secrets = os.path.join(self.tmp.name, "secrets")
        self.out = os.path.join(self.tmp.name, "health")
        self.p = [mock.patch.dict(os.environ, {"WHOOP_SECRETS_DIR": self.secrets,
                                               "WHOOP_OUTPUT_DIR": self.out,
                                               "WHOOP_TZ": TEST_TZ,
                                               "WHOOP_CREDENTIALS_FILE": os.path.join(self.tmp.name, "none.json"),
                                               "WHOOP_CLIENT_ID": "fake-client-id",
                                               "WHOOP_CLIENT_SECRET": FAKE_SECRET,
                                               "WHOOP_REDIRECT_URI": "https://example.com/whoop/callback"})]
        os.environ.pop("WHOOP_AUTH_REDIRECT_URL", None)
        os.environ.pop("WHOOP_RETENTION_DAYS", None)
        os.environ.pop("WHOOP_PKCE", None)
        for p in self.p:
            p.start()

    def tearDown(self):
        for p in self.p:
            p.stop()
        self.tmp.cleanup()

    def seed_token(self):
        wc.save_token({"access_token": FAKE_ACCESS_OLD, "refresh_token": FAKE_REFRESH_OLD,
                       "expires_in": 3600})

    def run_quiet(self, fn, *a, **k):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = fn(*a, **k)
        return rc, out.getvalue(), err.getvalue()

    def assertNoSecrets(self, *texts):
        for t in texts:
            for s in SENSITIVE:
                self.assertNotIn(s, t)

    def mode(self, path):
        return stat.S_IMODE(os.stat(path).st_mode)


class TestAtomicWrite(Base):
    def test_perms_and_no_temp_left(self):
        p = os.path.join(self.secrets, "x.json")
        wc.atomic_write_json(p, {"a": 1})
        self.assertEqual(self.mode(self.secrets), 0o700)
        self.assertEqual(self.mode(p), 0o600)
        self.assertEqual(json.load(open(p)), {"a": 1})
        self.assertEqual(os.listdir(self.secrets), ["x.json"])

    def test_failure_keeps_old_file(self):
        p = os.path.join(self.secrets, "x.json")
        wc.atomic_write_json(p, {"v": "old"})
        with mock.patch("os.replace", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                wc.atomic_write_json(p, {"v": "new"})
        self.assertEqual(json.load(open(p)), {"v": "old"})
        self.assertEqual(os.listdir(self.secrets), ["x.json"])

    def test_unserialisable_keeps_old_file(self):
        p = os.path.join(self.secrets, "x.json")
        wc.atomic_write_json(p, {"v": "old"})
        with self.assertRaises(TypeError):
            wc.atomic_write_json(p, {"v": object()})
        self.assertEqual(json.load(open(p)), {"v": "old"})

    def test_lock_is_exclusive(self):
        import fcntl
        with wc.token_lock():
            fd = os.open(wc.lock_path(), os.O_RDWR)
            with self.assertRaises(BlockingIOError):
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.close(fd)
        with wc.token_lock(timeout=1):
            pass


class TestAuth(Base):
    def test_url_and_state(self):
        rc, out, err = self.run_quiet(whoop_auth.cmd_url)
        self.assertEqual(rc, 0)
        saved = json.load(open(wc.state_path()))
        self.assertEqual(len(saved["state"]), 8)
        self.assertNotIn("code_verifier", saved)
        self.assertEqual(self.mode(wc.state_path()), 0o600)
        link = out.strip()
        self.assertEqual(self.mode(link), 0o600)
        page = open(link).read()
        self.assertIn("state=" + saved["state"], page)
        self.assertIn("scope=offline%20read%3Arecovery%20read%3Asleep%20read%3Acycles%20read%3Aworkout", page)
        self.assertIn(wc.AUTH_URL + "?response_type=code", page)
        self.assertNotIn("code_challenge", page)
        self.assertNotIn("example.com", out + err)   # redirect host is never printed
        self.assertNotIn(FAKE_SECRET, out + err + page)

    def test_states_are_random(self):
        self.assertEqual(len({whoop_auth.make_state() for _ in range(50)}), 50)

    def _exchange(self, redirect, http=None):
        with mock.patch.dict(os.environ, {"WHOOP_AUTH_REDIRECT_URL": redirect}):
            return self.run_quiet(whoop_auth.cmd_exchange, http=http or FakeHttp())

    def test_exchange_ok(self):
        self.run_quiet(whoop_auth.cmd_url)
        st = json.load(open(wc.state_path()))["state"]
        http = FakeHttp()
        rc, out, err = self._exchange(f"https://example.com/whoop/callback?code=abc&scope=x&state={st}", http)
        self.assertEqual(rc, 0, err)
        tok = wc.load_token()
        self.assertEqual(tok["refresh_token"], FAKE_REFRESH_OLD)
        self.assertEqual(self.mode(wc.token_path()), 0o600)
        self.assertFalse(os.path.exists(wc.state_path()))  # single use
        form = http.calls[0][2]
        self.assertEqual(form["grant_type"], "authorization_code")
        self.assertEqual(form["redirect_uri"], "https://example.com/whoop/callback")
        self.assertNoSecrets(out, err)

    def test_exchange_bad_state(self):
        self.run_quiet(whoop_auth.cmd_url)
        http = FakeHttp()
        rc, _, err = self._exchange("https://example.com/whoop/callback?code=abc&state=WRONG123", http)
        self.assertEqual(rc, 2)
        self.assertIn("state mismatch", err)
        self.assertEqual(http.calls, [])
        self.assertFalse(os.path.exists(wc.token_path()))

    def test_exchange_expired_state(self):
        self.run_quiet(whoop_auth.cmd_url)
        saved = json.load(open(wc.state_path()))
        saved["created_at"] -= 3600
        wc.atomic_write_json(wc.state_path(), saved)
        rc, _, err = self._exchange(f"https://example.com/whoop/callback?code=abc&state={saved['state']}")
        self.assertEqual(rc, 2)
        self.assertIn("expired", err)

    def test_exchange_wrong_host(self):
        self.run_quiet(whoop_auth.cmd_url)
        st = json.load(open(wc.state_path()))["state"]
        rc, _, err = self._exchange(f"https://evil.example.net/whoop/callback?code=abc&state={st}")
        self.assertEqual(rc, 2)

    def test_exchange_error_param(self):
        self.run_quiet(whoop_auth.cmd_url)
        rc, _, err = self._exchange("https://example.com/whoop/callback?error=access_denied&state=x")
        self.assertEqual(rc, 2)
        self.assertIn("access_denied", err)


class TestFetch(Base):
    def test_full_run(self):
        self.seed_token()
        http = FakeHttp(routes=ROUTES)
        rc, out, err = self.run_quiet(whoop_fetch.main, http=http, sleep=lambda s: None)
        self.assertEqual(rc, 0, err)
        # refresh happened first, and the new rotated token was written back
        self.assertEqual(http.calls[0][1], wc.TOKEN_URL)
        self.assertEqual(http.calls[0][2]["scope"], "offline")
        tok = wc.load_token()
        self.assertEqual(tok["refresh_token"], FAKE_REFRESH_NEW)
        self.assertEqual(tok["access_token"], FAKE_ACCESS_NEW)
        # API calls used the new access token
        self.assertTrue(all(c[3]["Authorization"] == "Bearer " + FAKE_ACCESS_NEW for c in http.calls[1:]))
        day = os.path.join(self.out, "2031-03-14.json")
        latest = os.path.join(self.out, "latest.json")
        self.assertEqual(self.mode(self.out), 0o700)
        self.assertEqual(self.mode(day), 0o600)
        self.assertEqual(self.mode(latest), 0o600)
        rec = json.load(open(latest))
        self.assertEqual(rec, json.load(open(day)))
        self.assertEqual(rec["date"], "2031-03-14")          # wake 08:15 local
        self.assertEqual(rec["recovery_score"], 67)          # skipped PENDING record
        self.assertEqual(rec["hrv_rmssd_ms"], 61.2)
        self.assertEqual(rec["resting_hr"], 52)
        self.assertEqual(rec["spo2"], 96.5)
        self.assertEqual(rec["skin_temp"], 33.9)
        self.assertEqual(rec["sleep_duration_h"], 7.25)      # light+deep+rem
        self.assertEqual(rec["stages_h"], {"in_bed": 7.75, "awake": 0.5, "light": 3.5,
                                           "deep_sws": 1.75, "rem": 2.0, "no_data": 0.0})
        self.assertEqual(rec["sleep_performance"], 91)
        self.assertEqual(rec["respiratory_rate"], 15.2)
        self.assertEqual(rec["strain"], 13.7)                # previous (completed) cycle
        self.assertEqual(rec["sleep_start"], local("2031-03-13T15:30:00Z"))
        self.assertEqual(rec["sleep_end"], local("2031-03-13T23:15:00Z"))
        self.assertEqual([w["sport_name"] for w in rec["workouts"]], ["weightlifting"])
        self.assertEqual(rec["workouts"][0]["start"], local("2031-03-13T10:00:00Z"))
        self.assertEqual(rec["workouts"][0]["duration_min"], 60.0)
        self.assertEqual([w["sport_name"] for w in rec["workouts_today"]], ["running"])
        self.assertTrue(rec["scored"])
        self.assertTrue(rec["fetched_at"].endswith(local("2031-03-13T00:00:00Z")[-6:]))
        self.assertEqual(rec["time_zone"], TEST_TZ)
        self.assertNoSecrets(out, err, json.dumps(rec))
        self.assertEqual([f for f in os.listdir(self.out) if f.startswith(".tmp")], [])

    def test_nap_is_excluded(self):
        self.seed_token()
        routes = dict(ROUTES)
        routes["/v2/activity/sleep/s-main"] = dict(SLEEP_MAIN, nap=True, id="s-main")
        routes["/v2/activity/sleep"] = {"records": [
            {"id": "nap1", "cycle_id": 2, "nap": True, "score_state": "SCORED",
             "start": "2031-03-14T05:00:00.000Z", "end": "2031-03-14T05:30:00.000Z"},
            dict(SLEEP_MAIN, id="real")]}
        rc, _, err = self.run_quiet(whoop_fetch.main, http=FakeHttp(routes=routes), sleep=lambda s: None)
        self.assertEqual(rc, 0, err)
        rec = json.load(open(os.path.join(self.out, "latest.json")))
        self.assertEqual(rec["sleep_end"], local("2031-03-13T23:15:00Z"))

    def test_not_scored_yet(self):
        self.seed_token()
        routes = dict(ROUTES)
        routes["/v2/recovery"] = {"records": [{"cycle_id": 3, "sleep_id": "s-p", "score_state": "PENDING_SCORE"}]}
        routes["/v2/activity/sleep/s-p"] = {"id": "s-p", "cycle_id": 3, "nap": False,
                                            "score_state": "PENDING_SCORE",
                                            "start": "2031-03-14T15:00:00.000Z", "end": "2031-03-14T22:50:00.000Z"}
        rc, _, _ = self.run_quiet(whoop_fetch.main, http=FakeHttp(routes=routes), sleep=lambda s: None)
        self.assertEqual(rc, 1)
        rec = json.load(open(os.path.join(self.out, "latest.json")))
        self.assertFalse(rec["scored"])
        self.assertIsNone(rec["recovery_score"])
        self.assertEqual(rec["date"], "2031-03-15")

    def test_refresh_failure(self):
        self.seed_token()
        before = open(wc.token_path()).read()
        rc, out, err = self.run_quiet(whoop_fetch.main, http=FakeHttp(refresh_status=400))
        self.assertEqual(rc, 3)
        self.assertEqual(err.strip(), "re-authorization needed")
        self.assertNoSecrets(out, err)
        self.assertEqual(open(wc.token_path()).read(), before)
        self.assertFalse(os.path.exists(self.out))

    def test_missing_token_file(self):
        rc, _, err = self.run_quiet(whoop_fetch.main, http=FakeHttp())
        self.assertEqual(rc, 3)
        self.assertIn("re-authorization needed", err)

    def test_api_401_after_refresh(self):
        self.seed_token()
        routes = dict(ROUTES, **{"/v2/recovery": wc.HttpError(401)})
        rc, out, err = self.run_quiet(whoop_fetch.main, http=FakeHttp(routes=routes))
        self.assertEqual(rc, 3)
        self.assertNoSecrets(out, err)

    def test_rate_limit_retry(self):
        self.seed_token()
        n = {"c": 0}
        base = FakeHttp(routes=ROUTES)

        def http(method, url, **k):
            if "/v2/recovery" in url and n["c"] == 0:
                n["c"] += 1
                raise wc.HttpError(429, retry_after="3")
            return base(method, url, **k)
        waits = []
        rc, _, err = self.run_quiet(whoop_fetch.main, http=http, sleep=waits.append)
        self.assertEqual(rc, 0, err)
        self.assertEqual(waits, [3])

    def test_server_error_gives_up(self):
        self.seed_token()
        routes = dict(ROUTES, **{"/v2/recovery": wc.HttpError(503)})
        rc, out, err = self.run_quiet(whoop_fetch.main, http=FakeHttp(routes=routes), sleep=lambda s: None)
        self.assertEqual(rc, 4)
        self.assertNoSecrets(out, err)


class TestConfig(Base):
    def test_credentials_file_used_when_env_missing(self):
        path = os.path.join(self.tmp.name, "client.json")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"client_id": "file-id", "client_secret": FAKE_SECRET,
                       "redirect_uri": "https://example.com/whoop/callback"}, f)
        env = {"WHOOP_CREDENTIALS_FILE": path, "WHOOP_CLIENT_ID": "", "WHOOP_CLIENT_SECRET": "",
               "WHOOP_REDIRECT_URI": ""}
        with mock.patch.dict(os.environ, env):
            c = wc.load_credentials(need_redirect=True)
        self.assertEqual((c["client_id"], c["client_secret"]), ("file-id", FAKE_SECRET))

    def test_credentials_file_must_be_0600(self):
        path = os.path.join(self.tmp.name, "client.json")
        with open(path, "w") as f:
            json.dump({"client_id": "file-id", "client_secret": FAKE_SECRET}, f)
        os.chmod(path, 0o644)
        with mock.patch.dict(os.environ, {"WHOOP_CREDENTIALS_FILE": path, "WHOOP_CLIENT_ID": "",
                                          "WHOOP_CLIENT_SECRET": ""}):
            with self.assertRaises(wc.ConfigError) as cm:
                wc.load_credentials()
        self.assertNotIn(FAKE_SECRET, str(cm.exception))

    def test_missing_credentials_message_has_no_values(self):
        with mock.patch.dict(os.environ, {"WHOOP_CLIENT_ID": "", "WHOOP_CLIENT_SECRET": ""}):
            rc, out, err = self.run_quiet(whoop_fetch.main, http=FakeHttp())
        self.assertEqual(rc, 2)
        self.assertIn("missing client_id, client_secret", err)

    def test_timezone_is_configurable(self):
        with mock.patch.dict(os.environ, {"WHOOP_TZ": "UTC"}):
            rec = whoop_fetch.build_record(None, SLEEP_MAIN, None, [], [])
        self.assertEqual(rec["sleep_end"], "2031-03-13T23:15:00+00:00")
        self.assertEqual(rec["date"], "2031-03-13")
        rec = whoop_fetch.build_record(None, SLEEP_MAIN, None, [], [])
        self.assertEqual(rec["date"], "2031-03-14")   # same sleep, Tokyo morning

    def test_bad_timezone(self):
        with mock.patch.dict(os.environ, {"WHOOP_TZ": "Not/AZone"}):
            with self.assertRaises(wc.ConfigError):
                wc.user_tz()

    def test_paths_default_to_home(self):
        with mock.patch.dict(os.environ, {"WHOOP_SECRETS_DIR": "", "WHOOP_OUTPUT_DIR": "",
                                          "HOME": "/tmp/fakehome"}):
            self.assertEqual(wc.secrets_dir(), "/tmp/fakehome/.secrets/whoop")
            self.assertEqual(wc.output_dir(), "/tmp/fakehome/health/whoop")

    def test_user_agent_is_neutral(self):
        self.assertTrue(wc.USER_AGENT.startswith("body-brief-whoop/"))


class TestPkceAndRedirect(Base):
    def test_pkce_pair_rfc7636(self):
        # S256 = BASE64URL(SHA256(ascii(verifier))) without padding (RFC 7636 section 4.2),
        # computed here independently via binascii.
        import binascii
        import hashlib
        verifier = "test-verifier-" + "x" * 40
        raw = binascii.b2a_base64(hashlib.sha256(verifier.encode("ascii")).digest(), newline=False).decode()
        expected = raw.rstrip("=").replace("+", "-").replace("/", "_")
        self.assertEqual(whoop_auth.pkce_challenge(verifier), expected)
        self.assertEqual(len(expected), 43)
        v, c = whoop_auth.make_pkce()
        self.assertTrue(43 <= len(v) <= 128)
        self.assertEqual(whoop_auth.pkce_challenge(v), c)

    def test_url_with_pkce_and_fragment(self):
        rc, out, _ = self.run_quiet(whoop_auth.cmd_url, pkce=True, response_mode="fragment")
        self.assertEqual(rc, 0)
        saved = json.load(open(wc.state_path()))
        page = open(out.strip()).read()
        self.assertIn("code_challenge=" + whoop_auth.pkce_challenge(saved["code_verifier"]), page)
        self.assertIn("code_challenge_method=S256", page)
        self.assertIn("response_mode=fragment", page)
        self.assertNotIn(saved["code_verifier"], page)

    def test_exchange_fragment_sends_verifier(self):
        self.run_quiet(whoop_auth.cmd_url, pkce=True, response_mode="fragment")
        saved = json.load(open(wc.state_path()))
        http = FakeHttp()
        url = f"https://example.com/whoop/callback#code=abc&scope=x&state={saved['state']}"
        rc, out, err = self.run_quiet(whoop_auth.cmd_exchange, http=http, pasted=url)
        self.assertEqual(rc, 0, err)
        self.assertIn("fragment", err)
        self.assertEqual(http.calls[0][2]["code_verifier"], saved["code_verifier"])
        self.assertEqual(http.calls[0][2]["code"], "abc")
        self.assertNotIn(saved["code_verifier"], out + err)

    def test_query_without_pkce_has_no_verifier(self):
        self.run_quiet(whoop_auth.cmd_url)
        st = json.load(open(wc.state_path()))["state"]
        http = FakeHttp()
        rc, _, err = self.run_quiet(whoop_auth.cmd_exchange, http=http,
                                    pasted=f"https://example.com/whoop/callback?code=abc&state={st}")
        self.assertEqual(rc, 0, err)
        self.assertNotIn("code_verifier", http.calls[0][2])
        self.assertIn("query", err)

    def test_split_redirect(self):
        self.assertEqual(whoop_auth.split_redirect("https://x.test/cb?code=1&state=s")[1], "query")
        self.assertEqual(whoop_auth.split_redirect("https://x.test/cb#code=1&state=s")[1], "fragment")
        self.assertEqual(whoop_auth.split_redirect("https://x.test/cb")[1], None)
        with self.assertRaises(ValueError):
            whoop_auth.split_redirect("https://x.test/cb?code=1#code=2")

    def test_fragment_error_param(self):
        self.run_quiet(whoop_auth.cmd_url)
        rc, _, err = self.run_quiet(whoop_auth.cmd_exchange, http=FakeHttp(),
                                    pasted="https://example.com/whoop/callback#error=access_denied&state=x")
        self.assertEqual(rc, 2)
        self.assertIn("access_denied", err)


class TestRevoke(Base):
    def test_full_revoke_calls_delete_and_removes_token(self):
        self.seed_token()
        http = FakeHttp()
        rc, out, err = self.run_quiet(whoop_auth.cmd_revoke, "full", http=http)
        self.assertEqual(rc, 0, err)
        self.assertEqual(http.calls[0][0], "DELETE")
        self.assertTrue(http.calls[0][1].endswith("/v2/user/access"))
        self.assertFalse(os.path.exists(wc.token_path()))
        self.assertNoSecrets(out, err)

    def test_token_only_revoke(self):
        self.seed_token()
        http = FakeHttp()
        rc, _, err = self.run_quiet(whoop_auth.cmd_revoke, "token", http=http)
        self.assertEqual(rc, 0, err)
        self.assertEqual(http.calls[0][1], wc.REVOKE_URL)
        self.assertEqual(http.calls[0][2]["token_type_hint"], "refresh_token")
        self.assertFalse(os.path.exists(wc.token_path()))

    def test_revoke_failure_keeps_token(self):
        self.seed_token()

        def http(*a, **k):
            raise wc.HttpError(503)
        rc, out, err = self.run_quiet(whoop_auth.cmd_revoke, "full", http=http)
        self.assertEqual(rc, 3)
        self.assertTrue(os.path.exists(wc.token_path()))
        self.assertNoSecrets(out, err)

    def test_local_only_with_data(self):
        self.seed_token()
        wc.atomic_write_json(os.path.join(self.out, "latest.json"), {"x": 1})
        rc, _, _ = self.run_quiet(whoop_auth.cmd_revoke, "local", delete_data=True, http=None)
        self.assertEqual(rc, 0)
        self.assertFalse(os.path.exists(wc.token_path()))
        self.assertEqual(os.listdir(self.out), [])


class TestRetention(Base):
    def _files(self, names):
        os.makedirs(self.out, exist_ok=True)
        for n in names:
            with open(os.path.join(self.out, n), "w") as f:
                f.write("{}")

    def test_default_is_30_days(self):
        self.assertEqual(wc.retention_days(), 30)

    def test_prunes_only_old_dated_files(self):
        import datetime as dt
        self._files(["2031-01-01.json", "2031-02-11.json", "2031-02-12.json", "2031-03-14.json",
                     "latest.json", "notes.json", "2031-02-30.json", "2031-01-01.json.bak"])
        n = whoop_fetch.prune_old(today=dt.date(2031, 3, 14))
        self.assertEqual(n, 2)   # 01-01 and 02-11 (< cutoff 02-12)
        self.assertEqual(sorted(os.listdir(self.out)),
                         ["2031-01-01.json.bak", "2031-02-12.json", "2031-02-30.json",
                          "2031-03-14.json", "latest.json", "notes.json"])

    def test_zero_disables(self):
        import datetime as dt
        self._files(["2020-01-01.json"])
        with mock.patch.dict(os.environ, {"WHOOP_RETENTION_DAYS": "0"}):
            self.assertEqual(whoop_fetch.prune_old(today=dt.date(2031, 3, 14)), 0)
        self.assertEqual(os.listdir(self.out), ["2020-01-01.json"])

    def test_bad_value(self):
        with mock.patch.dict(os.environ, {"WHOOP_RETENTION_DAYS": "-3"}):
            with self.assertRaises(wc.ConfigError):
                wc.retention_days()

    def test_never_touches_token(self):
        import datetime as dt
        self.seed_token()
        with mock.patch.dict(os.environ, {"WHOOP_OUTPUT_DIR": self.secrets}):
            whoop_fetch.prune_old(days=1, today=dt.date(2031, 3, 14))
        self.assertTrue(os.path.exists(wc.token_path()))

    def test_main_prunes_after_write(self):
        self._files(["2000-01-01.json"])
        self.seed_token()
        rc, _, err = self.run_quiet(whoop_fetch.main, http=FakeHttp(routes=ROUTES), sleep=lambda s: None)
        self.assertEqual(rc, 0, err)
        self.assertIn("pruned=1", err)
        self.assertNotIn("2000-01-01.json", os.listdir(self.out))
        self.assertIn("latest.json", os.listdir(self.out))


if __name__ == "__main__":
    unittest.main(verbosity=2)
