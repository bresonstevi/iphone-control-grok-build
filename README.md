# iphone-control

A small, safety-first command-line bridge that lets a coding agent (or you) drive a spare iPhone from a Mac. It talks to [WebDriverAgent](https://github.com/appium/WebDriverAgent) (WDA) running on the phone over USB and exposes simple commands: `status`, `start`, `screenshot`, `tree`, `tap`, `tap-label`, `type`, `swipe`, `home`, `launch`, `terminate`, `lock-check`, `apps`, and `session`.

Safety is enforced in code, not only in docs:

- Taps, label taps, and typing are refused (exit code 3) when the target or text matches a risky word (send, buy, pay, delete, confirm, sign out, and more), unless `--approved` is passed.
- A tap whose target element cannot be identified is refused unless `--approved`.
- Typing 13+ digit runs (card-like numbers) or into password fields is refused unless `--approved`.
- Only apps on an allowlist can be launched (unless `--force`).
- Every command, including blocked and failed ones, is appended to an action log.

Python 3 standard library only. No pip installs.

## Layout

```
iphone-control/
  AGENTS.md            rules and workflow for coding agents
  apps/README.md       optional per-app notes (git-ignored by default)
  bridge/
    iphone             bash wrapper (symlink-safe)
    iphone.py          the bridge CLI
    policy.json        app allowlist, risky words, device config
    resign.sh          rebuild and re-sign WDA (build-for-testing)
    test_tap_guard.py  unit tests for the safety checks
    README.md          full command reference
```

## Requirements

- A Mac running macOS with Xcode installed and signed in to an Apple ID (a free Personal Team works; signing then expires every 7 days).
- A spare iPhone with Developer Mode enabled (Settings, Privacy & Security, Developer Mode), connected by USB and trusted by the Mac.
- `iproxy` from libimobiledevice (`brew install libimobiledevice`).
- `/usr/bin/python3` (the macOS system Python 3.9+ is fine).
- A checkout of WebDriverAgent.

## Setup

1. Clone this repo to `~/iphone-control` (the default paths in `policy.json` assume that location; edit them if you put it elsewhere).
   After downloading, make the scripts runnable: `chmod +x bridge/iphone bridge/resign.sh`
2. Clone WebDriverAgent next to the bridge:
   ```
   cd ~/iphone-control
   git clone https://github.com/appium/WebDriverAgent.git
   ```
3. Find your values:
   - Device UDID: `xcrun xctrace list devices` or `idevice_id -l`.
   - Team ID: Xcode, Settings, Accounts, or open `WebDriverAgent.xcodeproj` and look under Signing & Capabilities.
   - Choose a unique bundle id such as `com.example.WebDriverAgentRunner` (replace `com.example` with a reverse-DNS prefix you own).
4. Edit `bridge/policy.json`, `device` section: set `udid` to YOUR_DEVICE_UDID, `team_id` to YOUR_TEAM_ID, `wda_bundle_id`, and check `iproxy_bin` (`which iproxy`). Replace the `PLACEHOLDER.*` app entries with real bundle ids, or delete them.
5. Build and sign WDA: `./bridge/resign.sh`.
6. On the phone, trust the developer profile: Settings, General, VPN & Device Management, your Apple Development profile, Trust.
7. Unlock the phone, then:
   ```
   ./bridge/iphone start
   ./bridge/iphone status
   ./bridge/iphone screenshot
   ```
8. Optional: `ln -s ~/iphone-control/bridge/iphone /usr/local/bin/iphone`.

Run the safety tests with `cd bridge && python3 -m unittest test_tap_guard`.

See `bridge/README.md` for every command and flag.

## Safety rules

- Use a spare test phone only. Never connect a personal or work phone that holds real accounts you care about.
- Keep personal, health, and financial data off the phone. Screenshots and element trees capture whatever is on screen.
- Nothing gets sent, posted, bought, deleted, or signed in or out without the owner's explicit approval for that exact action. `--approved` and `--force` only record a yes that a human already gave.
- An agent must not edit `policy.json`, the bridge code, or the logs as part of a phone task.
- The bridge never kills processes and has no unlock, lock, or password actions.
- Screenshots (`shots/`) and the action log (`logs/`) can contain private information. They are git-ignored; keep it that way.
- The code blocks are a backstop, not a permission system. Review `logs/actions.jsonl` regularly.

## Using Grok CLI / Grok Build as the coding agent

This repo works well with Grok CLI (Grok Build) as the agent that operates the phone or maintains the bridge.

1. Install Grok CLI and sign in, following the official Grok Build documentation.
2. Start it from the repo root (`cd ~/iphone-control && grok`) so it picks up `AGENTS.md`, which contains the hard rules and the required workflow (status first, screenshot or tree before every action, prefer `tap-label`).
3. Optional: make the rules global by copying `AGENTS.md` into a user-level skill or rules file (for example a skill named `iphone`), so any Grok session can drive the phone safely without being in this directory.
4. Keep phone tasks and code tasks separate. For a phone task, ask Grok to use only `bridge/iphone` commands. For a change to the bridge itself, ask for it explicitly, then review the diff and run `python3 -m unittest test_tap_guard` in `bridge/` before using it.
5. Run Grok in a mode where shell commands need your approval, and say no to any command that passes `--approved` or `--force` unless you just approved that exact action.
6. Read the screenshot files Grok saves (it can open PNGs) and check `logs/actions.jsonl` after a session.

## Re-signing

With a free Personal Team, the WDA install expires after 7 days. Run `./bridge/resign.sh`, stop the old WDA `xcodebuild` run yourself, then `./bridge/iphone start`.

## License

MIT. See `LICENSE`.
