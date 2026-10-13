# AGENTS.md for ~/iphone-control

This directory holds the iPhone bridge and the WebDriverAgent checkout. You can also copy these instructions into your coding agent's global rules or skill file so they apply everywhere.

## iPhone bridge (a spare test iPhone)

There is a working bridge on this Mac that controls the owner's SPARE test iPhone through WebDriverAgent (WDA) at http://127.0.0.1:8100 (USB, via iproxy).

- CLI: `~/iphone-control/bridge/iphone <command>` (same as `~/iphone-control/bridge/iphone`, or `./iphone` from inside `~/iphone-control/bridge`)
- Full docs: `~/iphone-control/bridge/README.md`
- Every command (including blocked and failed ones) is logged to `~/iphone-control/logs/actions.jsonl`. The owner reviews that log.
- Exit codes: 0 ok, 1 runtime error, 2 usage error, 3 blocked by policy.

## Hard rules (never break these)

1. Spare test phone only. This is not anyone's personal phone and must never be treated as one.
2. Never enter, read, view, copy, or summarize personal, health, or financial data. If such data appears on screen, stop, do not transcribe it, and tell the owner.
3. Never send, buy, pay, submit, post, delete, or sign in (or sign out) without the owner's explicit approval for that exact action in the current conversation.
4. Never pass `--approved` or `--force` on your own. They exist only to record that the owner already said yes to that specific action. If a command exits 3 (blocked), stop and ask the owner.
5. Never edit `~/iphone-control/bridge/policy.json`, `iphone.py`, `iphone`, `resign.sh`, or any other safety code from inside a phone task. Changing the bridge is a separate coding task that the owner must request.
6. Never kill, restart, or start xcodebuild or iproxy yourself except through `iphone start`. Never kill any process.
7. All actions are logged. Do not try to hide, edit, or delete `actions.jsonl`.

## Required workflow

1. Always run `iphone status` first.
2. If it is not `ready: true`, run `iphone start` (the phone must be unlocked; ask the owner to unlock it if start times out). Then `iphone status` again.
3. Before ANY tap, tap-label, type, or swipe: take `iphone screenshot` and/or `iphone tree` so you know what is on screen and what is under the point. Read the screenshot file to look at it.
4. Prefer `tap-label "text"` over raw coordinates. Use coordinates taken from the latest `tree` output (x, y, w, h; tap the center).
5. After an action, screenshot or tree again to confirm the result.
6. If a task only asks you to look, use only `status`, `screenshot`, and `tree`.

## Commands

| Command | What it does |
| --- | --- |
| `iphone status` | WDA ready?, iOS version, iproxy/xcodebuild running, session id. Read-only. |
| `iphone start` | Starts iproxy and the WDA run if needed, waits up to 90 s. Never kills anything. |
| `iphone screenshot [--out PATH]` | Saves a PNG (default `~/iphone-control/shots/shot-YYYYmmdd-HHMMSS.png`) and prints the path. Read-only. |
| `iphone tree [--max N] [--json]` | Lists visible elements: type, label, name, value, x, y, w, h, enabled. Read-only. |
| `iphone tap X Y [--approved]` | Taps a point. Refused (exit 3) if the element there matches a risky word, or if the bridge cannot identify the element at that point. |
| `iphone tap-label "text" [--exact] [--approved]` | Finds an element by label/name and taps it. Refused on risky words. |
| `iphone type "text" [--approved]` | Types into the focused field. Refused on risky words, 13+ digit runs, or secure (password) fields. |
| `iphone swipe X1 Y1 X2 Y2 [--duration S]` | Drag gesture. |
| `iphone home` | Presses Home (does not lock). |
| `iphone launch BUNDLE [--force]` | Launches an app on the allowlist in policy.json (`iphone apps`). Others are refused. |
| `iphone terminate BUNDLE` | Closes an app. |
| `iphone lock-check` / `iphone unlock-check` | Prints whether the phone is locked. |
| `iphone apps` | Prints the app allowlist. No phone call. |
| `iphone session` | Ensures a WDA session exists. |

Global flags: `--url URL`, `--timeout SECONDS`.

`bridge/resign.sh` re-signs WDA weekly (free Apple signing expires after 7 days). Only run it when the owner asks.

Risky words (blocked without `--approved`): send, buy, pay, submit, purchase, order, delete, checkout, confirm, transfer, post, publish, erase, reset, remove, sign out, log out, subscribe, donate, place order, book. The bridge blocking an action is a backstop, not permission: the rules above apply even when the bridge would allow something.
