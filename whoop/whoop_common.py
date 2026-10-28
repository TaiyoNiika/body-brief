"""Shared helpers for the Body Brief WHOOP fetcher (standard library only).

Nothing in this module logs tokens, secrets, authorization codes or raw API responses.

Configuration (all optional, read at call time):
  WHOOP_SECRETS_DIR        default ~/.secrets/whoop        (0700; token + OAuth state)
  WHOOP_OUTPUT_DIR         default ~/health/whoop          (0700; daily JSON files)
  WHOOP_CREDENTIALS_FILE   default <WHOOP_SECRETS_DIR>/client.json (must be 0600)
  WHOOP_TZ                 IANA zone name, e.g. Europe/Berlin; default: $TZ, then system local
  WHOOP_RETENTION_DAYS     default 30; 0 disables pruning of dated files
"""
import contextlib
import datetime as dt
import fcntl
import json
import os
import stat
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

AUTH_URL = "https://api.prod.whoop.com/oauth/oauth2/auth"
TOKEN_URL = "https://api.prod.whoop.com/oauth/oauth2/token"
REVOKE_URL = "https://api.prod.whoop.com/oauth/oauth2/revoke"
API_BASE = "https://api.prod.whoop.com/developer"
SCOPES = "offline read:recovery read:sleep read:cycles read:workout"
USER_AGENT = "body-brief-whoop/0.1 (+uses the WHOOP API)"
DEFAULT_RETENTION_DAYS = 30


class ConfigError(Exception):
    """Missing or unsafe configuration. Message never contains secret values."""


# ---------------------------------------------------------------- paths / config

def _home_path(*parts):
    return os.path.join(os.path.expanduser("~"), *parts)


def secrets_dir():
    return os.environ.get("WHOOP_SECRETS_DIR") or _home_path(".secrets", "whoop")


def output_dir():
    return os.environ.get("WHOOP_OUTPUT_DIR") or _home_path("health", "whoop")


def token_path():
    return os.path.join(secrets_dir(), "token.json")


def state_path():
    return os.path.join(secrets_dir(), "oauth_state.json")


def lock_path():
    return os.path.join(secrets_dir(), "token.lock")


def credentials_path():
    return os.environ.get("WHOOP_CREDENTIALS_FILE") or os.path.join(secrets_dir(), "client.json")


def user_tz():
    """WHOOP_TZ, then TZ, then the system local zone. Invalid names raise ConfigError."""
    name = (os.environ.get("WHOOP_TZ") or os.environ.get("TZ") or "").strip().lstrip(":")
    if name:
        try:
            from zoneinfo import ZoneInfo
            return ZoneInfo(name)
        except Exception:
            raise ConfigError("WHOOP_TZ/TZ is not a valid IANA time zone name") from None
    return dt.datetime.now().astimezone().tzinfo


def retention_days():
    raw = os.environ.get("WHOOP_RETENTION_DAYS", "").strip()
    if not raw:
        return DEFAULT_RETENTION_DAYS
    try:
        n = int(raw)
    except ValueError:
        raise ConfigError("WHOOP_RETENTION_DAYS must be a whole number (0 = keep forever)") from None
    if n < 0:
        raise ConfigError("WHOOP_RETENTION_DAYS must be >= 0")
    return n


def _check_private_file(path):
    st = os.stat(path)
    if stat.S_IMODE(st.st_mode) & 0o077:
        raise ConfigError(f"{os.path.basename(path)} must be mode 0600 (chmod 600)")
    if hasattr(os, "getuid") and st.st_uid != os.getuid():
        raise ConfigError(f"{os.path.basename(path)} must be owned by the current user")


def load_credentials(need_secret=True, need_redirect=False):
    """Environment first (WHOOP_CLIENT_ID / WHOOP_CLIENT_SECRET / WHOOP_REDIRECT_URI),
    then the 0600 JSON file {"client_id", "client_secret", "redirect_uri"}."""
    creds = {
        "client_id": os.environ.get("WHOOP_CLIENT_ID", "").strip(),
        "client_secret": os.environ.get("WHOOP_CLIENT_SECRET", "").strip(),
        "redirect_uri": os.environ.get("WHOOP_REDIRECT_URI", "").strip(),
    }
    path = credentials_path()
    if os.path.exists(path):
        _check_private_file(path)
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except ValueError:
            raise ConfigError("credentials file is not valid JSON") from None
        for k in creds:
            if not creds[k] and isinstance(data.get(k), str):
                creds[k] = data[k].strip()
    missing = [k for k, need in (("client_id", True), ("client_secret", need_secret),
                                  ("redirect_uri", need_redirect)) if need and not creds[k]]
    if missing:
        raise ConfigError("missing " + ", ".join(missing) +
                          " (set env vars or write them to the 0600 credentials file)")
    return creds


# ---------------------------------------------------------------- logging / files

def log(msg):
    """Short status line to stderr. Callers must never pass secrets here."""
    try:
        now = dt.datetime.now(user_tz())
    except ConfigError:
        now = dt.datetime.now().astimezone()
    print(f"[whoop {now.isoformat(timespec='seconds')}] {msg}", file=sys.stderr)


def ensure_dir(path):
    os.makedirs(path, mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)


def atomic_write_json(path, obj):
    """Write JSON to a 0600 temp file in the same dir, fsync, then rename over the target."""
    d = os.path.dirname(path)
    ensure_dir(d)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=d)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        dfd = os.open(d, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


@contextlib.contextmanager
def token_lock(timeout=120):
    """Exclusive advisory lock so two processes never refresh the same (single-use) refresh token."""
    ensure_dir(secrets_dir())
    fd = os.open(lock_path(), os.O_RDWR | os.O_CREAT, 0o600)
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() > deadline:
                    raise TimeoutError("token lock busy")
                time.sleep(0.5)
        yield
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def load_token():
    with open(token_path(), encoding="utf-8") as f:
        return json.load(f)


def save_token(resp, previous=None):
    """Persist a token endpoint response. Keeps the old refresh token only if WHOOP omitted a new one."""
    now = int(time.time())
    refresh = resp.get("refresh_token") or (previous or {}).get("refresh_token")
    tok = {
        "access_token": resp["access_token"],
        "refresh_token": refresh,
        "token_type": resp.get("token_type", "bearer"),
        "scope": resp.get("scope", ""),
        "expires_at": now + int(resp.get("expires_in", 3600)),
        "obtained_at": now,
    }
    atomic_write_json(token_path(), tok)
    return tok


# ---------------------------------------------------------------- HTTP

class HttpError(Exception):
    def __init__(self, status, retry_after=None, error=None):
        super().__init__(f"HTTP {status}" + (f" ({error})" if error else ""))
        self.status = status
        self.retry_after = retry_after
        self.error = error  # OAuth "error" field only (e.g. invalid_grant), never the full body


def _oauth_error_field(raw):
    try:
        e = json.loads(raw).get("error")
    except Exception:
        return None
    # Only short machine-readable codes are surfaced.
    return e if isinstance(e, str) and len(e) <= 40 and e.replace("_", "").isalnum() else None


def http_request(method, url, data=None, headers=None, timeout=30):
    """Returns parsed JSON (or None). Raises HttpError with status (+ OAuth error code) only."""
    body = None
    hdrs = {"Accept": "application/json", "User-Agent": USER_AGENT}
    hdrs.update(headers or {})
    if data is not None:
        body = urllib.parse.urlencode(data).encode()
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        ra = e.headers.get("Retry-After") or e.headers.get("X-RateLimit-Reset")
        try:
            err = _oauth_error_field(e.read())
        except Exception:
            err = None
        raise HttpError(e.code, retry_after=ra, error=err) from None
    except urllib.error.URLError:
        raise HttpError(0) from None


def post_token(form, http=http_request):
    return http("POST", TOKEN_URL, data=form)


# ---------------------------------------------------------------- time

def parse_ts(ts):
    return dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))


def to_local(ts, tz=None):
    """ISO timestamp from WHOOP (UTC) -> ISO string in the user's zone."""
    if not ts:
        return None
    return parse_ts(ts).astimezone(tz or user_tz()).isoformat(timespec="seconds")
