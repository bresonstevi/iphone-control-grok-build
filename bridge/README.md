# iPhone control bridge

Local controller for the spare iPhone through WebDriverAgent. Run it from this directory:

```bash
./iphone status
./iphone start
```

`iphone` is a bash wrapper. It resolves symlinks and execs `/usr/bin/python3` on `iphone.py`. Python 3.9 standard library only.

Device id, port, signing team, bundle id, and paths live in `policy.json`. Commands read that file. They are not hardcoded in the scripts.

## Hard rules

Spare phone only. No personal or sensitive data ever. Nothing gets sent, posted, bought, or deleted without the owner's explicit approval (--approved is only for after the owner says yes).

Keep personal and sensitive data off this phone. Screenshots save whatever is on the display, so the same rule covers `screenshot` and `tree`.

`--approved` records that the owner already said yes. It is the gate for risky taps, for a tap whose target element cannot be identified, and for typing. It is not a shortcut you take on your own.

## Weekly re-sign

Free Apple development signing expires after 7 days. Once a week, run:

```bash
./resign.sh
```

`resign.sh` runs `xcodebuild build-for-testing` with `-allowProvisioningUpdates` and appends the log to `~/iphone-control/wda-build.log`. It reads the destination, team, bundle id, and paths from `policy.json`.

The script does not stop or kill any process. After it finishes, stop the old WebDriverAgent xcodebuild run yourself, then run:

```bash
./iphone start
```

The phone must be unlocked while WDA starts.

## Trust the developer profile

After the first install, and again whenever iOS asks, unlock the phone and trust the developer certificate:

1. Open Settings.
2. Open General.
3. Open VPN & Device Management.
4. Trust the developer profile for this signing team.

USB must be connected. `iphone start` runs `iproxy` so WDA on the phone is available at `http://127.0.0.1:8100`. If the profile is untrusted, `/status` stays down. `iphone start` will not kill a stuck run. Stop the old run yourself and start again after you trust the profile.

## Global flags

These work before or after the subcommand:

- `--url URL`: WDA base URL. Default is `device.default_url` in `policy.json` (`http://127.0.0.1:8100`).
- `--timeout SECONDS`: HTTP timeout. Default is 30. Must be greater than 0.

```bash
./iphone --url http://127.0.0.1:8100 --timeout 20 status
./iphone screenshot --timeout 60
```

## Commands

### status

```bash
./iphone status
```

GET `/status`. Prints `ready`, the iOS version, the phone IP, whether `iproxy` and the WebDriverAgent `xcodebuild` process are running (`pgrep -f`), and the current session id if `bridge/.session` or `/status` has one. Exit 0 when the report is printed. `ready: false` means WDA is not up yet.

### start

```bash
./iphone start
```

If `http://127.0.0.1:8100/status` is not ready:

1. Start `iproxy` with `nohup` when it is not already running. Log: `~/iphone-control/iproxy.log`.
2. If status is still not ready, start `xcodebuild test-without-building` with `nohup` when that run is not already going. Log: `~/iphone-control/wda-run.log`.
3. Poll `/status` for up to 90 seconds.

The phone must be unlocked. This command never kills an existing `iproxy` or `xcodebuild`. If some other WebDriverAgent `xcodebuild` is already running, start leaves it alone and keeps polling.

### screenshot

```bash
./iphone screenshot
./iphone screenshot --out ~/iphone-control/shots/now.png
```

GET `/screenshot`, base64-decode the body, and write a PNG. The default path is `~/iphone-control/shots/shot-YYYYmmdd-HHMMSS.png` (local time of the Mac). Prints the path. The action log stores that path in `screenshot`.

### tree

```bash
./iphone tree
./iphone tree --max 40
./iphone tree --json
```

GET `/session/{id}/source?format=json`. If that fails, GET `/source?format=json`. Prints visible elements that have a label, name, or value. The type has the `XCUIElementType` prefix removed. Value text is truncated to 60 characters. Each text row contains type, label, name, value, `x`, `y`, `w`, `h`, and `enabled`. `--max` defaults to 80. `--json` prints a JSON array with the same limit.

### tap

```bash
./iphone tap 200 420
./iphone tap 200 420 --approved
```

POST `/session/{id}/wda/tap` with `{"x": X, "y": Y}`. If that route fails, POST W3C pointer actions to `/session/{id}/actions`.

Before the tap, the command loads the element tree and finds the smallest visible element whose frame contains the point. If that element's label or name matches a risky word, the tap is refused with exit code 3 unless you pass `--approved`. When the smallest element has no label and no name, the nearest labeled ancestor is checked (an icon inside a Send button).

`tap X Y` also refuses with exit code 3 unless you pass `--approved` when the element at the point cannot be identified. That covers a source tree that cannot be read (including a failed fetch, bad JSON, or an unexpected error while reading the tree), a point that hits no visible element, and an element whose label and name are empty on it and on every ancestor. The refusal happens before any tap request, so nothing is sent to `/wda/tap` or `/actions`. With `--approved`, the tap still runs and a note on stderr says why it would have been blocked.

### tap-label

```bash
./iphone tap-label "Search"
./iphone tap-label "Done" --exact
./iphone tap-label "Send" --approved
```

Finds elements with POST `/session/{id}/elements` and strategy `predicate string`.

- `--exact`: `label == 'text'`
- default: `label CONTAINS[c] 'text' OR name CONTAINS[c] 'text'`

Quotes in the text are escaped. The first visible match is clicked with POST `/session/{id}/element/{id}/click`.

Exit code 3 unless `--approved` when the text you typed, or the matched element's label or name, contains a risky word. Matching is case-insensitive and uses word boundaries, so `pay` matches `Pay` and does not match `paypal`.

### type

```bash
./iphone type "hello"
./iphone type "4111111111111111" --approved
```

POST `/session/{id}/wda/keys` with `{"value": ["h", "e", "l", "l", "o"]}` (one string per character).

Exit code 3 unless `--approved` when:

- the text contains a risky word, or
- the text contains 13 or more consecutive digits, or
- the focused element is a secure text field (`SecureTextField`).

The focused element comes from GET `/session/{id}/element/active` and its `type` attribute. If that lookup fails, the command notes it and still applies the text checks. There is no lock, unlock, or password-reset action.

### swipe

```bash
./iphone swipe 200 700 200 200
./iphone swipe 200 700 200 200 --duration 0.3
```

POST `/session/{id}/wda/dragfromtoforduration` with `fromX`, `fromY`, `toX`, `toY`, and `duration`. Duration defaults to 0.3 seconds and must be greater than 0.

### home

```bash
./iphone home
```

POST `/wda/homescreen`. This presses Home. It does not lock the phone.

### launch

```bash
./iphone launch com.apple.mobilesafari
./iphone launch com.example.Other --force
```

POST `/session/{id}/wda/apps/launch` with `{"bundleId": "..."}`. The bundle id must be an exact key in `policy.json` `allowed_apps`. Anything else exits 3 unless you pass `--force`.

Keys that start with `PLACEHOLDER` never match a real app. `iphone apps` still prints them so you can see what to fill in. Replace `PLACEHOLDER.app1`, `PLACEHOLDER.app2`, and `PLACEHOLDER.app3` with the real bundle ids before those apps can launch. `--force` is the only override, and it is for a bundle you mean to open.

The session is created with no `bundleId`, so creating a session launches nothing by itself.

### terminate

```bash
./iphone terminate com.apple.mobilesafari
```

POST `/session/{id}/wda/apps/terminate` with `{"bundleId": "..."}`.

### lock-check

```bash
./iphone lock-check
./iphone unlock-check
```

`unlock-check` is an alias. GET `/wda/locked` and print `locked: true` or `locked: false`.

Lock and unlock are not implemented.

### apps

```bash
./iphone apps
```

Prints each allowlisted bundle id and its name from `policy.json`. No phone call.

### session

```bash
./iphone session
```

Reuses `bridge/.session` when GET `/session/{id}` succeeds. Otherwise reuses a session id from `/status` when that id is valid. Otherwise POST `/session` with `{"capabilities":{"alwaysMatch":{}}}` and stores the new id. No app is launched.

## Safety layer

Enforced in `iphone.py`:

| Action | Rule | Exit |
| --- | --- | --- |
| launch | Exact allowlist match. Placeholder ids are refused. | 3, unless `--force` |
| tap-label | Risky word in the request or in the matched label or name. | 3, unless `--approved` |
| tap | Risky word on the element under that point, or the element cannot be identified (unreadable tree, no element at the point, or no label or name). | 3, unless `--approved` |
| type | Risky word, 13+ consecutive digits, or a secure text field. | 3, unless `--approved` |

Risky words are the `risky_words` list in `policy.json` (`send`, `buy`, `pay`, `submit`, `purchase`, `order`, `delete`, `checkout`, `confirm`, `transfer`, `post`, `publish`, `erase`, `reset`, `remove`, `sign out`, `log out`, `subscribe`, `donate`, `place order`, `book`). Phrases match as phrases. A blocked attempt is logged with `"result":"blocked"` and the phone is not tapped or typed.

`tap X Y` refuses with exit code 3 when the element at the point cannot be identified, unless `--approved`. The refusal is logged as `"result":"blocked"` and no tap request is sent. With `--approved`, the tap proceeds and stderr gets a note describing why it would have been blocked.

## Logs

Every command, including blocked and failed commands, appends one JSON line to `~/iphone-control/logs/actions.jsonl`:

```json
{"ts":"2026-10-11T15:04:05-04:00","command":"tap","args":{"x":10,"y":20,"approved":false,"url":null,"timeout":30.0},"result":"ok","screenshot":null}
```

- `ts` is ISO 8601 in the Mac's local time zone, with a numeric offset.
- `screenshot` is the PNG path for `screenshot`, otherwise null.
- Typed text longer than 40 characters is stored as the first 10 characters plus `...(N chars)`, where N is the full length.

The log directory is created when a command runs.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The command finished. |
| 1 | Runtime error (WDA down, no matching element, bad response). |
| 2 | Usage error. |
| 3 | Blocked by policy. |

## Config

`policy.json`:

- `allowed_apps`: bundle id to display name. Replace every `PLACEHOLDER.*` key with the real bundle id.
- `risky_words`: word-boundary list used by tap, tap-label, and type.
- `device`: UDID `YOUR_DEVICE_UDID`, port `8100`, team `YOUR_TEAM_ID`, WDA bundle `com.example.WebDriverAgentRunner`, `iproxy` path, WebDriverAgent project path, DerivedData path, and the log and screenshot paths.

`bridge/.session` is created when a session is opened. You can delete that file yourself when you want a fresh WDA session. The bridge does not delete it for you.

## What you run, and what the tools refuse to do

You run `./iphone` and `./resign.sh`. Those entry points do not include lock, unlock, or a kill switch. `start` and `resign.sh` leave existing `iproxy` and `xcodebuild` processes alone. Stop an old WDA run yourself before you start a new one after re-signing.
