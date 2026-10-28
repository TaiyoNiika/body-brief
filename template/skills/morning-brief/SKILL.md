---
name: morning-brief
description: Write the daily Body Brief briefing from ~/health/whoop/latest.json. General wellness only, with a non-medical disclaimer.
---

1. Run `python3 ~/body-brief/whoop/whoop_fetch.py` with the owner's `WHOOP_TZ` and `WHOOP_RETENTION_DAYS`.
   - Exit 3: tell the owner WHOOP needs re-authorization and offer to start it (getting-started steps 6–7). Do not guess numbers.
   - Exit 1: today's data isn't scored yet; say so, and retry once in about an hour.
   - Exit 2 or 4: say the pull failed (config or WHOOP error) and offer a screenshot of the WHOOP app as fallback.
2. Read `latest.json` (and, for trends, up to 7 previous dated files if present). Check `date` is today in the owner's zone; if not, say the data is stale.
3. Write at most ~8 short lines in the owner's language:
   - Recovery score, HRV, resting HR, sleep duration/performance, yesterday's strain, workouts.
   - Compare with their own recent days, not with population norms.
   - One or two concrete, gentle suggestions for today (e.g. "keep training easy-to-moderate", "aim for an earlier bedtime", "hydrate"). No diagnoses, no conditions, no supplements or medication, no extreme advice.
   - If something looks unusual for several days, suggest checking in with a doctor; don't speculate why.
   - Label statements: checked (from today's file) / inferred / judgment; say what is missing.
4. End with: "General wellness info, not medical advice. Data via the WHOOP API."
5. Deliver only in the owner's private chat or the channel they chose. Never post health data elsewhere.
