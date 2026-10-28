# Body Brief — template draft (not exported)

Text-only draft laid out the way the bot-template exporter expects. Nothing here has been packed
or published.

- **Name:** Body Brief
- **Description (short):** A wearable-data morning brief. It reads your own device data and gives you a short,
  non-medical daily briefing. Currently supports WHOOP (through your own WHOOP developer app);
  more devices are planned. Uses the WHOOP API;
  not affiliated with WHOOP.
- **Memories:** `memories/profile.md`, `memories/log/setup.md`
- **Skills:** `getting-started`, `body-brief-install`, `morning-brief`
- **gettingStarted:** `getting-started`
- **Routines (job text only; created during getting-started with consent):**
  `routines/morning-brief.md`, `routines/weekly-summary.md`
- **Plugins:** none. No custom MCP servers. No secrets, tokens or account slots.

Before packing:
1. Push the repo, pick the release commit, fill `{{RAW_BASE}}` / `{{COMMIT_SHA}}` in
   `skills/body-brief-install/SKILL.md`.
2. Run `python3 tools/gen_manifest.py` at that commit so the hash list matches it.
3. Run `python3 tools/clean_check.py` — every count must be 0.
