# Privacy Policy — [YOUR APP NAME]

*Template. Replace every [BRACKETED] item, host it at a URL you control, and enter that URL as
the Privacy Policy URL of your WHOOP app. This is not legal advice; check what applies where you live.*

Last updated: [DATE]

## Who this app is for
[YOUR APP NAME] is a personal app created and used by [YOUR NAME OR HANDLE] ("I") to read
**my own** WHOOP data through the WHOOP API. It is not offered to other people. [YOUR APP NAME]
uses the WHOOP API; it is not made, endorsed or sponsored by WHOOP.

## What data is read
With my explicit authorization on WHOOP's consent screen, the app reads: recovery
(e.g. recovery score, HRV, resting heart rate, SpO2, skin temperature), sleep, physiological
cycles (strain) and workouts. Scopes requested: `offline read:recovery read:sleep read:cycles read:workout`.

## Where it is stored
- Data is stored only as files on my own bot computer, in a private directory (permissions 0700/0600).
- OAuth tokens are stored in a separate private directory on the same computer.
- Daily files are deleted automatically after [30] days; the most recent summary (`latest.json`) is kept until I delete it.
- Other software running on the same computer under the same user account (including other
  bots I run there) can technically read these files.

## How it is used
The data is used only to produce my own morning summary and general wellness suggestions.
It is **not medical advice** and is not used for diagnosis or treatment.
The data is processed by my AI assistant only to write messages to me. It is not sold, rented,
shared with other people, used for advertising, or used to train or improve any AI model.

## Third parties
WHOOP (data source). [YOUR AI ASSISTANT PROVIDER] processes the text of my summaries on my behalf
to generate replies to me. No other third parties.

## Security
Data is fetched over HTTPS. Secrets and tokens are never printed or logged by the app.
If I find unauthorized access to WHOOP data, I will notify WHOOP as its API terms require.

## Your choices / deleting data
I can disconnect at any time (`whoop_auth.py revoke --delete-data`, or remove the app in my
WHOOP account settings), which revokes access and deletes the local token and data files.

## Contact
[CONTACT EMAIL]
