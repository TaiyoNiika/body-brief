#!/usr/bin/env python3
"""Daily WHOOP pull for Body Brief (standard library only).

  python3 whoop_fetch.py

Refreshes the token first (WHOOP refresh tokens are single-use; the new one is written back
atomically under a file lock), then writes <output>/YYYY-MM-DD.json and latest.json, with all
times in the user's zone (WHOOP_TZ). Afterwards, dated files older than WHOOP_RETENTION_DAYS
(default 30; 0 = keep forever) are deleted. latest.json and the token are never pruned.
Exit codes: 0 ok (scored), 1 ok but not scored yet, 2 config error, 3 re-authorization needed,
4 API error.
"""
import datetime as dt
import os
import re
import sys
import time
import urllib.parse

import whoop_common as wc


class ReauthNeeded(Exception):
    pass


def refresh(http=wc.http_request):
    creds = wc.load_credentials(need_secret=True)
    cid, csec = creds["client_id"], creds["client_secret"]
    with wc.token_lock():
        try:
            old = wc.load_token()
        except (FileNotFoundError, ValueError):
            raise ReauthNeeded()
        if not old.get("refresh_token"):
            raise ReauthNeeded()
        try:
            resp = wc.post_token({
                "grant_type": "refresh_token",
                "refresh_token": old["refresh_token"],
                "client_id": cid,
                "client_secret": csec,
                "scope": "offline",
            }, http=http)
        except wc.HttpError as e:
            if e.status in (400, 401, 403):
                raise ReauthNeeded()
            raise
        if not resp or not resp.get("access_token"):
            raise ReauthNeeded()
        return wc.save_token(resp, previous=old)


class Api:
    def __init__(self, access_token, http=wc.http_request, sleep=time.sleep):
        self._auth = {"Authorization": "Bearer " + access_token}
        self._http = http
        self._sleep = sleep

    def get(self, path, params=None):
        url = wc.API_BASE + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        for attempt in range(4):
            try:
                return self._http("GET", url, headers=self._auth)
            except wc.HttpError as e:
                if e.status == 401:
                    raise ReauthNeeded()
                if e.status == 429 or e.status >= 500 or e.status == 0:
                    if attempt == 3:
                        raise
                    try:
                        wait = min(int(float(e.retry_after)), 60) if e.retry_after else 5 * (attempt + 1)
                    except ValueError:
                        wait = 5 * (attempt + 1)
                    wc.log(f"{path} returned {e.status}; retrying in {wait}s")
                    self._sleep(wait)
                    continue
                raise

    def collection(self, path, max_pages=4, **params):
        params.setdefault("limit", 25)
        out, nxt = [], None
        for _ in range(max_pages):
            p = dict(params)
            if nxt:
                p["nextToken"] = nxt
            page = self.get(path, p) or {}
            out.extend(page.get("records") or [])
            nxt = page.get("next_token")
            if not nxt:
                break
        return out


def _h(ms):
    return None if ms is None else round(ms / 3_600_000, 2)


def _iso_utc(t):
    return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _parse(ts):
    return wc.parse_ts(ts)


def workout_view(w):
    s = w.get("score") or {}
    return {
        "sport_name": w.get("sport_name"),
        "start": wc.to_local(w.get("start")),
        "end": wc.to_local(w.get("end")),
        "duration_min": round((_parse(w["end"]) - _parse(w["start"])).total_seconds() / 60, 1)
        if w.get("start") and w.get("end") else None,
        "scored": w.get("score_state") == "SCORED",
        "strain": s.get("strain"),
        "average_heart_rate": s.get("average_heart_rate"),
        "max_heart_rate": s.get("max_heart_rate"),
        "kilojoule": s.get("kilojoule"),
        "distance_meter": s.get("distance_meter"),
    }


def build_record(recovery, sleep, prev_cycle, workouts_prev, workouts_today, now=None):
    """Pure function: API objects -> output dict. All times in the user's zone."""
    tz = wc.user_tz()
    now = now or dt.datetime.now(tz)
    rs = (recovery or {}).get("score") or {}
    ss = (sleep or {}).get("score") or {}
    st = ss.get("stage_summary") or {}
    cs = (prev_cycle or {}).get("score") or {}
    light, sws, rem = (st.get("total_light_sleep_time_milli"), st.get("total_slow_wave_sleep_time_milli"),
                       st.get("total_rem_sleep_time_milli"))
    asleep = None if None in (light, sws, rem) else light + sws + rem
    wake = sleep.get("end") if sleep else None
    date = (_parse(wake).astimezone(tz).date() if wake else now.date()).isoformat()
    rec_scored = (recovery or {}).get("score_state") == "SCORED"
    sleep_scored = (sleep or {}).get("score_state") == "SCORED"
    return {
        "date": date,
        "recovery_score": rs.get("recovery_score"),
        "hrv_rmssd_ms": None if rs.get("hrv_rmssd_milli") is None else round(rs["hrv_rmssd_milli"], 1),
        "resting_hr": rs.get("resting_heart_rate"),
        "spo2": rs.get("spo2_percentage"),
        "skin_temp": rs.get("skin_temp_celsius"),
        "user_calibrating": rs.get("user_calibrating"),
        "sleep_start": wc.to_local(sleep.get("start")) if sleep else None,
        "sleep_end": wc.to_local(wake),
        "sleep_duration_h": _h(asleep),
        "sleep_performance": ss.get("sleep_performance_percentage"),
        "sleep_efficiency": ss.get("sleep_efficiency_percentage"),
        "sleep_consistency": ss.get("sleep_consistency_percentage"),
        "stages_h": {
            "in_bed": _h(st.get("total_in_bed_time_milli")),
            "awake": _h(st.get("total_awake_time_milli")),
            "light": _h(light),
            "deep_sws": _h(sws),
            "rem": _h(rem),
            "no_data": _h(st.get("total_no_data_time_milli")),
        },
        "disturbance_count": st.get("disturbance_count"),
        "respiratory_rate": ss.get("respiratory_rate"),
        "strain": cs.get("strain"),
        "strain_cycle": {
            "start": wc.to_local(prev_cycle.get("start")) if prev_cycle else None,
            "end": wc.to_local(prev_cycle.get("end")) if prev_cycle else None,
            "scored": (prev_cycle or {}).get("score_state") == "SCORED",
            "kilojoule": cs.get("kilojoule"),
        },
        "workouts": [workout_view(w) for w in workouts_prev],
        "workouts_today": [workout_view(w) for w in workouts_today],
        "fetched_at": now.astimezone(tz).isoformat(timespec="seconds"),
        "scored": bool(rec_scored and sleep_scored),
        "score_states": {
            "recovery": (recovery or {}).get("score_state"),
            "sleep": (sleep or {}).get("score_state"),
            "cycle": (prev_cycle or {}).get("score_state"),
        },
        "time_zone": str(tz),
        "source": "WHOOP API v2",
    }


def collect(api, now=None):
    now = now or dt.datetime.now(wc.user_tz())
    recs = api.collection("/v2/recovery", max_pages=1, limit=10)
    if not recs:
        return build_record(None, None, None, [], [], now)
    recovery = next((r for r in recs if r.get("score_state") == "SCORED"), recs[0])

    sleep = None
    if recovery.get("sleep_id"):
        sleep = api.get(f"/v2/activity/sleep/{recovery['sleep_id']}")
    if not sleep or sleep.get("nap"):
        sleeps = api.collection("/v2/activity/sleep", max_pages=1, limit=10)
        main = [s for s in sleeps if not s.get("nap")]
        sleep = next((s for s in main if s.get("cycle_id") == recovery.get("cycle_id")),
                     main[0] if main else None)

    cycles = api.collection("/v2/cycle", max_pages=1, limit=5)
    prev_cycle, cur_cycle = None, None
    for i, c in enumerate(cycles):  # descending by start
        if c.get("id") == recovery.get("cycle_id"):
            cur_cycle = c
            prev_cycle = cycles[i + 1] if i + 1 < len(cycles) else None
            break
    if cur_cycle is None and len(cycles) >= 2:
        cur_cycle, prev_cycle = cycles[0], cycles[1]

    workouts_prev, workouts_today = [], []
    if prev_cycle and prev_cycle.get("start"):
        ws = api.collection("/v2/activity/workout", start=_iso_utc(_parse(prev_cycle["start"])))
        split = _parse(cur_cycle["start"]) if cur_cycle and cur_cycle.get("start") else None
        for w in sorted(ws, key=lambda w: w.get("start", "")):
            if split and _parse(w["start"]) >= split:
                workouts_today.append(w)
            else:
                workouts_prev.append(w)
    return build_record(recovery, sleep, prev_cycle, workouts_prev, workouts_today, now)


def write_outputs(rec):
    out = wc.output_dir()
    wc.ensure_dir(out)
    day = os.path.join(out, f"{rec['date']}.json")
    wc.atomic_write_json(day, rec)
    wc.atomic_write_json(os.path.join(out, "latest.json"), rec)
    return day


DATED = re.compile(r"^(\d{4})-(\d{2})-(\d{2})\.json$")


def prune_old(days=None, today=None, out=None):
    """Delete <output>/YYYY-MM-DD.json older than `days` days. Returns the number deleted.

    Only regular files whose whole name is a valid date + .json are touched; latest.json,
    the token (which lives in a different directory) and anything else are left alone.
    """
    days = wc.retention_days() if days is None else days
    if days <= 0:
        return 0
    out = out or wc.output_dir()
    today = today or dt.datetime.now(wc.user_tz()).date()
    cutoff = today - dt.timedelta(days=days)
    removed = 0
    try:
        names = os.listdir(out)
    except FileNotFoundError:
        return 0
    for name in names:
        m = DATED.match(name)
        if not m:
            continue
        try:
            d = dt.date(int(m[1]), int(m[2]), int(m[3]))
        except ValueError:
            continue
        path = os.path.join(out, name)
        if d < cutoff and os.path.isfile(path) and not os.path.islink(path):
            os.unlink(path)
            removed += 1
    return removed


def main(http=wc.http_request, sleep=time.sleep):
    try:
        tok = refresh(http=http)
        rec = collect(Api(tok["access_token"], http=http, sleep=sleep))
    except ReauthNeeded:
        print("re-authorization needed", file=sys.stderr)
        return 3
    except wc.ConfigError as e:
        wc.log(f"config error: {e}")
        return 2
    except TimeoutError:
        wc.log("token lock busy; try again later")
        return 4
    except wc.HttpError as e:
        wc.log(f"WHOOP API error ({e})")
        return 4
    path = write_outputs(rec)
    pruned = prune_old()
    wc.log(f"wrote {os.path.basename(path)} and latest.json, scored={rec['scored']}, pruned={pruned}")
    return 0 if rec["scored"] else 1


if __name__ == "__main__":
    sys.exit(main())
