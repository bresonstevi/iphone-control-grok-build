#!/usr/bin/python3
"""Spare-iPhone bridge: WebDriverAgent commands with an allowlist and risky-word gate.

Device ids, ports, and paths come from policy.json. This tool never kills
iproxy or xcodebuild. It does not lock or unlock the phone.
"""

import argparse
import base64
import datetime
import fcntl
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
DEFAULT_ACTIONS_LOG = os.path.expanduser("~/iphone-control/logs/actions.jsonl")
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
VALUE_LIMIT = 60

DEVICE_KEYS = (
    "udid",
    "port",
    "team_id",
    "wda_bundle_id",
    "iproxy_bin",
    "wda_dir",
    "wda_project",
    "wda_scheme",
    "derived_data",
    "wda_run_log",
    "wda_build_log",
    "iproxy_log",
    "shots_dir",
    "actions_log",
    "default_url",
)


class BridgeError(Exception):
    def __init__(self, message, code=1):
        super(BridgeError, self).__init__(message)
        self.code = code


class Blocked(BridgeError):
    def __init__(self, message):
        super(Blocked, self).__init__(message, code=3)


def truthy(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes")
    return False


def as_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def json_num(value):
    number = as_float(value)
    if number.is_integer() and abs(number) < 1e15:
        return int(number)
    return number


def fmt_num(value):
    return str(json_num(value))


def posix_escape(text):
    out = []
    for ch in str(text):
        if ch in ".*+?()[]{}|\\^$":
            out.append("\\")
        out.append(ch)
    return "".join(out)


def dig(obj, *keys):
    cur = obj
    for key in keys:
        if not isinstance(cur, dict) or key not in cur:
            return None
        cur = cur[key]
    return cur


def snippet(payload):
    if payload is None:
        return "empty response"
    if isinstance(payload, str):
        text = payload.strip().replace("\n", " ")
    else:
        try:
            text = json.dumps(payload)
        except (TypeError, ValueError):
            text = str(payload)
    if len(text) > 300:
        return text[:300] + "..."
    return text


def wda_error_message(payload):
    if not isinstance(payload, dict):
        return None
    value = payload.get("value")
    if isinstance(value, dict) and value.get("error"):
        message = value.get("message") or value.get("error")
        text = str(message).strip()
        if len(text) > 500:
            text = text[:500] + "..."
        return text or str(value.get("error"))
    if payload.get("error") and "value" not in payload:
        return str(payload.get("message") or payload.get("error"))
    return None


def extract_session_id(payload):
    if not isinstance(payload, dict):
        return None
    for key in ("sessionId", "session_id"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    value = payload.get("value")
    if isinstance(value, dict):
        for key in ("sessionId", "session_id"):
            nested = value.get(key)
            if isinstance(nested, str) and nested.strip():
                return nested.strip()
    return None


def element_id(obj):
    if isinstance(obj, str) and obj.strip():
        return obj.strip()
    if not isinstance(obj, dict):
        return None
    element = obj.get("ELEMENT")
    if isinstance(element, str) and element:
        return element
    for key, value in obj.items():
        if key.startswith("element-") and isinstance(value, str) and value:
            return value
    nested = obj.get("value")
    if isinstance(nested, dict):
        return element_id(nested)
    return None


def url_quote(value):
    return urllib.parse.quote(str(value), safe="")


def now_et_datetime():
    try:
        return datetime.datetime.now().astimezone()
    except Exception:
        return None


def now_et_iso():
    current = now_et_datetime()
    if current is not None:
        return current.isoformat(timespec="seconds")
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime())
    if len(stamp) >= 5 and stamp[-5] in "+-" and stamp[-3] != ":":
        stamp = stamp[:-2] + ":" + stamp[-2:]
    return stamp


def shot_stamp():
    current = now_et_datetime()
    if current is not None:
        return current.strftime("%Y%m%d-%H%M%S")
    return time.strftime("%Y%m%d-%H%M%S", time.localtime())


def matching_risky_word(text, words):
    if text is None:
        return None
    hay = str(text).lower()
    if not hay:
        return None
    for word in words:
        if not isinstance(word, str):
            continue
        cleaned = word.strip().lower()
        if not cleaned:
            continue
        pattern = r"\b%s\b" % re.escape(cleaned)
        if re.search(pattern, hay):
            return word
    return None


def has_long_digit_run(text):
    return re.search(r"\d{13,}", text or "") is not None


def redact_typed(text):
    if isinstance(text, str) and len(text) > 40:
        return text[:10] + "...(%d chars)" % len(text)
    return text


def args_for_log(args):
    data = {}
    for key, value in vars(args).items():
        if key == "command":
            continue
        data[key] = value
    if getattr(args, "command", None) == "type" and isinstance(data.get("text"), str):
        data["text"] = redact_typed(data["text"])
    return data


def launch_block_reason(bundle, allowed):
    if not isinstance(bundle, str) or not bundle.strip():
        return "bundle id is empty."
    if any(ch.isspace() for ch in bundle):
        return "bundle id must not contain whitespace."
    if bundle.startswith("PLACEHOLDER.") or bundle.upper().startswith("PLACEHOLDER"):
        return (
            "placeholder bundle ids never match a real app. "
            "Edit policy.json and replace the placeholder with the real bundle id."
        )
    if bundle not in allowed:
        return "it is not in policy.json allowed_apps."
    return None


def escape_predicate(text):
    return (
        text.replace("\\", "\\\\")
        .replace("'", "\\'")
        .replace("\n", " ")
        .replace("\r", " ")
    )


def predicate_for(text, exact):
    escaped = escape_predicate(text)
    if exact:
        return "label == '%s'" % escaped
    return "label CONTAINS[c] '%s' OR name CONTAINS[c] '%s'" % (escaped, escaped)


def frame_of(node):
    if not isinstance(node, dict):
        return None
    rect = node.get("rect")
    if rect is None:
        rect = node.get("frame")
    if isinstance(rect, dict):
        x = as_float(rect.get("x", rect.get("X", 0)))
        y = as_float(rect.get("y", rect.get("Y", 0)))
        w = as_float(rect.get("width", rect.get("w", 0)))
        h = as_float(rect.get("height", rect.get("h", 0)))
        return (x, y, w, h)
    if isinstance(rect, str):
        nums = re.findall(r"-?\d+(?:\.\d+)?", rect)
        if len(nums) >= 4:
            return tuple(float(num) for num in nums[:4])
    return None


def frame_contains(frame, x, y):
    fx, fy, fw, fh = frame
    if fw <= 0 or fh <= 0:
        return False
    return fx <= x <= fx + fw and fy <= y <= fy + fh


def is_visible(node):
    if not isinstance(node, dict):
        return False
    if "visible" in node:
        return truthy(node.get("visible"))
    if "isVisible" in node:
        return truthy(node.get("isVisible"))
    return True


def is_enabled(node):
    if not isinstance(node, dict):
        return True
    if "enabled" in node:
        return truthy(node.get("enabled"))
    if "isEnabled" in node:
        return truthy(node.get("isEnabled"))
    return True


def element_type_name(node):
    raw = "Element"
    if isinstance(node, dict):
        raw = node.get("type") or node.get("elementType") or "Element"
    raw = str(raw)
    prefix = "XCUIElementType"
    if raw.startswith(prefix):
        raw = raw[len(prefix):]
    return raw or "Element"


def text_or_empty(value):
    if value is None or isinstance(value, (bool, dict, list)):
        return ""
    return str(value).strip()


def truncate_text(value, limit):
    text = "" if value is None else str(value)
    text = text.replace("\r", " ").replace("\n", " ")
    if len(text) <= limit:
        return text
    if limit <= 3:
        return text[:limit]
    return text[: limit - 3] + "..."


def iter_nodes(node, parent=None):
    if not isinstance(node, dict):
        return
    yield node, parent
    children = node.get("children") or []
    if isinstance(children, list):
        for child in children:
            for item in iter_nodes(child, node):
                yield item


def label_and_name(node):
    found = []
    if not isinstance(node, dict):
        return found
    for key in ("label", "name"):
        value = node.get(key)
        if isinstance(value, str) and value.strip():
            found.append(value)
    return found


def hit_texts(tree, x, y):
    best = None
    best_key = None
    index = 0
    parents = {}
    for node, parent in iter_nodes(tree):
        index += 1
        parents[id(node)] = parent
        if not is_visible(node):
            continue
        frame = frame_of(node)
        if frame is None or not frame_contains(frame, x, y):
            continue
        area = frame[2] * frame[3]
        key = (area, -index)
        if best_key is None or key < best_key:
            best = node
            best_key = key
    if best is None:
        return []
    texts = label_and_name(best)
    if texts:
        return texts
    parent = parents.get(id(best))
    while parent is not None:
        texts = label_and_name(parent)
        if texts:
            return texts
        parent = parents.get(id(parent))
    return []


def _lookup_detail(error):
    text = str(error).strip()
    if text:
        return text
    if isinstance(error, BaseException):
        name = error.__class__.__name__
        if name:
            return name
    return "unknown error"


def tap_guard(tree, x, y, risky_words, approved, lookup_error=None):
    """Return (texts, note) or raise Blocked. Does not use the network.

    texts are the label and name of the smallest visible element at (x, y),
    or of the nearest ancestor that has one. note is None when the tap is
    allowed with nothing to warn about. When the tap would be blocked and
    approved is true, note describes why. Otherwise Blocked is raised
    (exit code 3) and the caller must not send a tap.
    """
    x_num = float(x)
    y_num = float(y)
    point = "%s,%s" % (fmt_num(x_num), fmt_num(y_num))
    texts = []
    kind = None
    detail = None

    if lookup_error is not None:
        kind = "lookup"
        detail = _lookup_detail(lookup_error)
    else:
        try:
            found = hit_texts(tree, x_num, y_num)
            if not isinstance(found, list):
                raise TypeError("element lookup returned %s" % type(found).__name__)
            texts = found
        except Exception as exc:
            texts = []
            kind = "lookup"
            detail = _lookup_detail(exc)
        else:
            if not texts:
                kind = "unknown"
            else:
                try:
                    words = risky_words if risky_words is not None else []
                    for piece in texts:
                        word = matching_risky_word(piece, words)
                        if word:
                            kind = "risky"
                            detail = word
                            break
                except Exception as exc:
                    texts = []
                    kind = "lookup"
                    detail = _lookup_detail(exc)

    if kind is None:
        return texts, None

    if kind == "lookup":
        reason = "could not read what element is at that point (%s)" % detail
        tail = "Take a screenshot/tree first, or pass --approved only after the owner says yes."
    elif kind == "unknown":
        reason = (
            "unknown element at that point (no visible element contains the point, "
            "or the element and its ancestors have no readable label or name)"
        )
        tail = "Take a screenshot/tree first, or pass --approved only after the owner says yes."
    else:
        reason = "element text matches risky word '%s'" % detail
        tail = "Pass --approved only after the owner says yes."

    message = "refusing to tap %s: %s. %s" % (point, reason, tail)
    if approved:
        return texts, "would have blocked this tap: %s. %s" % (reason, tail)
    raise Blocked(message)


def collect_rows(tree):
    rows = []
    for node, _parent in iter_nodes(tree):
        if not is_visible(node):
            continue
        label = node.get("label") if isinstance(node.get("label"), str) else ""
        name = node.get("name") if isinstance(node.get("name"), str) else ""
        value = text_or_empty(node.get("value"))
        if not (label.strip() or name.strip() or value):
            continue
        frame = frame_of(node) or (0.0, 0.0, 0.0, 0.0)
        rows.append({
            "type": element_type_name(node),
            "label": label,
            "name": name,
            "value": truncate_text(value, VALUE_LIMIT),
            "x": json_num(frame[0]),
            "y": json_num(frame[1]),
            "w": json_num(frame[2]),
            "h": json_num(frame[3]),
            "enabled": is_enabled(node),
        })
    return rows


def format_row(row):
    return " ".join([
        row["type"],
        "label=%s" % json.dumps(row["label"], ensure_ascii=False),
        "name=%s" % json.dumps(row["name"], ensure_ascii=False),
        "value=%s" % json.dumps(row["value"], ensure_ascii=False),
        "x=%s" % row["x"],
        "y=%s" % row["y"],
        "w=%s" % row["w"],
        "h=%s" % row["h"],
        "enabled=%s" % ("true" if row["enabled"] else "false"),
    ])


def unwrap_source(payload):
    if isinstance(payload, str):
        payload = json.loads(payload)
    if not isinstance(payload, dict):
        raise BridgeError("element source was not a JSON object")
    value = payload.get("value", payload)
    if isinstance(value, str):
        value = json.loads(value)
    if (
        isinstance(value, dict)
        and "type" not in value
        and "children" not in value
        and isinstance(value.get("value"), (dict, str))
    ):
        value = value.get("value")
        if isinstance(value, str):
            value = json.loads(value)
    if isinstance(value, list):
        return {"type": "Root", "visible": True, "children": value}
    if not isinstance(value, dict):
        raise BridgeError("element source had an unexpected shape")
    return value


def parse_status(payload):
    value = payload.get("value") if isinstance(payload, dict) else None
    if not isinstance(value, dict):
        value = payload if isinstance(payload, dict) else {}
    ready = truthy(value.get("ready"))
    ios = dig(value, "os", "version")
    if ios is None:
        ios = dig(value, "ios", "version")
    if ios is None:
        ios = "unknown"
    ip_addr = dig(value, "ios", "ip")
    if ip_addr is None:
        ip_addr = dig(value, "ios", "ipAddress")
    if ip_addr is None:
        ip_addr = "unknown"
    return ready, str(ios), str(ip_addr), extract_session_id(payload)


def status_is_ready(payload):
    ready, _ios, _ip, _sid = parse_status(payload)
    return ready


def parse_locked(payload):
    if not isinstance(payload, dict):
        raise BridgeError("unexpected /wda/locked response")
    value = payload.get("value")
    if isinstance(value, dict):
        if "locked" in value:
            value = value["locked"]
        elif "value" in value:
            value = value["value"]
    if isinstance(value, str):
        low = value.strip().lower()
        if low in ("true", "yes", "1"):
            return True
        if low in ("false", "no", "0"):
            return False
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in (0, 1):
        return bool(value)
    raise BridgeError("unexpected /wda/locked response: %s" % snippet(payload))


def format_pids(pids):
    if not pids:
        return "not running"
    return "running (%s)" % ", ".join(pids)


def w3c_tap_body(x, y):
    return {
        "actions": [
            {
                "type": "pointer",
                "id": "finger1",
                "parameters": {"pointerType": "touch"},
                "actions": [
                    {
                        "type": "pointerMove",
                        "duration": 0,
                        "x": json_num(x),
                        "y": json_num(y),
                    },
                    {"type": "pointerDown", "button": 0},
                    {"type": "pause", "duration": 50},
                    {"type": "pointerUp", "button": 0},
                ],
            }
        ]
    }


def decode_png_b64(value):
    if isinstance(value, dict):
        value = value.get("value") or value.get("screenshot") or ""
    if not isinstance(value, str) or not value.strip():
        raise BridgeError("screenshot response did not contain base64 data")
    if value.strip().startswith("data:") and "," in value:
        value = value.split(",", 1)[1]
    compact = "".join(value.split())
    pad = (-len(compact)) % 4
    try:
        raw = base64.b64decode(compact + ("=" * pad))
    except Exception as exc:
        raise BridgeError("could not decode screenshot base64: %s" % exc)
    if not raw.startswith(PNG_MAGIC):
        raise BridgeError("decoded screenshot is not a PNG")
    return raw


def load_policy(path=None):
    path = path or os.path.join(SCRIPT_DIR, "policy.json")
    try:
        with open(path, "r", encoding="utf-8") as handle:
            policy = json.load(handle)
    except FileNotFoundError:
        raise BridgeError("missing policy file: %s" % path)
    except json.JSONDecodeError as exc:
        raise BridgeError("policy.json is not valid JSON: %s" % exc)
    if not isinstance(policy, dict):
        raise BridgeError("policy.json must be a JSON object")
    for key in ("allowed_apps", "risky_words", "device"):
        if key not in policy:
            raise BridgeError("policy.json missing key: %s" % key)
    if not isinstance(policy["allowed_apps"], dict):
        raise BridgeError("allowed_apps must be an object of bundle id to name")
    if not isinstance(policy["risky_words"], list):
        raise BridgeError("risky_words must be a list")
    device = policy["device"]
    if not isinstance(device, dict):
        raise BridgeError("device must be an object")
    missing = [key for key in DEVICE_KEYS if key not in device]
    if missing:
        raise BridgeError("policy.json device missing: %s" % ", ".join(missing))
    return policy


def try_load_policy():
    try:
        return load_policy()
    except Exception:
        return None


def actions_log_path(policy):
    if isinstance(policy, dict):
        device = policy.get("device")
        if isinstance(device, dict) and device.get("actions_log"):
            return os.path.expanduser(str(device["actions_log"]))
    return DEFAULT_ACTIONS_LOG


def build_record(command, args, result, screenshot):
    return {
        "ts": now_et_iso(),
        "command": command,
        "args": args,
        "result": result,
        "screenshot": screenshot,
    }


def append_jsonl(path, record):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    line = json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
    with open(path, "a", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            handle.write(line)
            handle.flush()
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def session_file_path():
    return os.path.join(SCRIPT_DIR, ".session")


def read_session():
    path = session_file_path()
    try:
        with open(path, "r", encoding="utf-8") as handle:
            sid = handle.read().strip()
    except FileNotFoundError:
        return None
    return sid or None


def write_session(sid):
    path = session_file_path()
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(sid + "\n")
    os.replace(tmp, path)


def positive_float(text):
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError("expected a number")
    if not value > 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return value


def nonnegative_int(text):
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("expected an integer")
    if value < 0:
        raise argparse.ArgumentTypeError("must be 0 or greater")
    return value


def move_global_flags(argv):
    """Accept --url and --timeout before or after the subcommand."""
    moved = []
    rest = []
    index = 0
    flags = ("--url", "--timeout")
    while index < len(argv):
        arg = argv[index]
        equals_flag = None
        for flag in flags:
            if arg.startswith(flag + "="):
                equals_flag = arg
                break
        if equals_flag is not None:
            moved.append(equals_flag)
            index += 1
            continue
        if arg in flags:
            moved.append(arg)
            if index + 1 >= len(argv):
                index += 1
                break
            moved.append(argv[index + 1])
            index += 2
            continue
        rest.append(arg)
        index += 1
    return moved + rest


class BridgeParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write("error: %s\n" % message)
        try:
            policy = try_load_policy()
            append_jsonl(
                actions_log_path(policy),
                build_record("usage", {"message": message}, "error", None),
            )
        except Exception as exc:
            sys.stderr.write("error: could not write action log: %s\n" % exc)
        raise SystemExit(2)


def build_parser():
    parser = BridgeParser(
        prog="iphone",
        description="Control the spare iPhone through WebDriverAgent on localhost.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Hard rules: Spare phone only. No personal or sensitive data ever. "
            "Nothing gets sent, posted, bought, or deleted without the owner's explicit approval "
            "(--approved is only for after the owner says yes).\n"
            "\n"
            "Global flags may appear before or after the subcommand:\n"
            "  --url URL       WDA base URL. Default comes from policy.json.\n"
            "  --timeout SECS  HTTP timeout in seconds. Default: 30.\n"
            "\n"
            "Exit codes: 0 success, 1 runtime error, 2 usage error, 3 blocked by policy."
        ),
    )
    parser.add_argument(
        "--url",
        default=None,
        help="WDA base URL. Default: policy.json device.default_url.",
    )
    parser.add_argument(
        "--timeout",
        type=positive_float,
        default=30.0,
        help="HTTP timeout in seconds. Default: 30.",
    )
    sub = parser.add_subparsers(dest="command", metavar="command", required=True)

    sub.add_parser(
        "status",
        help="Show WDA ready state, iOS version, IP, iproxy, xcodebuild, and session id.",
    )
    sub.add_parser(
        "start",
        help="Start iproxy and WDA if /status is not ready. Never kills processes.",
    )

    screenshot = sub.add_parser("screenshot", help="Save a PNG screenshot and print the path.")
    screenshot.add_argument(
        "--out",
        default=None,
        help="Output PNG path. Default: ~/iphone-control/shots/shot-YYYYmmdd-HHMMSS.png.",
    )

    tree = sub.add_parser(
        "tree",
        help="List visible elements that have a label, name, or value.",
    )
    tree.add_argument("--max", type=nonnegative_int, default=80, help="Maximum rows. Default: 80.")
    tree.add_argument("--json", action="store_true", help="Print a JSON array instead of text lines.")

    tap = sub.add_parser(
        "tap",
        help="Tap a screen point. Refuses an unknown or risky element unless --approved.",
    )
    tap.add_argument("x", type=float, help="X in screen points.")
    tap.add_argument("y", type=float, help="Y in screen points.")
    tap.add_argument(
        "--approved",
        action="store_true",
        help="Tap anyway only after the owner says yes. Required when the element is unknown or risky.",
    )

    tap_label = sub.add_parser(
        "tap-label",
        help="Tap the first visible element whose label or name matches text.",
    )
    tap_label.add_argument("text", help="Label text to find.")
    tap_label.add_argument(
        "--exact",
        action="store_true",
        help="Match label == text. Default is a case-insensitive contains match on label or name.",
    )
    tap_label.add_argument(
        "--approved",
        action="store_true",
        help="Required when the text or the matched element hits a risky word.",
    )

    type_cmd = sub.add_parser(
        "type",
        help="Type text into the focused field. Risky text and secure fields need --approved.",
    )
    type_cmd.add_argument("text", help="Characters to send.")
    type_cmd.add_argument(
        "--approved",
        action="store_true",
        help="Required for risky words, 13+ digit runs, or a secure text field.",
    )

    swipe = sub.add_parser("swipe", help="Drag from one point to another.")
    swipe.add_argument("x1", type=float)
    swipe.add_argument("y1", type=float)
    swipe.add_argument("x2", type=float)
    swipe.add_argument("y2", type=float)
    swipe.add_argument("--duration", type=positive_float, default=0.3, help="Seconds. Default: 0.3.")

    sub.add_parser("home", help="Press the home button. Does not lock the phone.")

    launch = sub.add_parser("launch", help="Launch an allowlisted bundle id. Placeholders are refused.")
    launch.add_argument("bundle", help="Bundle id, for example com.apple.mobilesafari.")
    launch.add_argument(
        "--force",
        action="store_true",
        help="Launch even if the bundle is not on the allowlist.",
    )

    terminate = sub.add_parser("terminate", help="Terminate an app by bundle id.")
    terminate.add_argument("bundle", help="Bundle id to terminate.")

    sub.add_parser("lock-check", help="Print whether the phone is locked. Does not lock or unlock.")
    sub.add_parser("unlock-check", help="Alias of lock-check.")
    sub.add_parser("apps", help="Print the allowlist from policy.json.")
    sub.add_parser("session", help="Reuse the saved WDA session, or create one that launches no app.")
    return parser


class Client(object):
    def __init__(self, base_url, timeout, policy):
        self.base_url = str(base_url).rstrip("/")
        self.timeout = float(timeout)
        self.policy = policy
        self.device = policy["device"]
        self.allowed_apps = policy["allowed_apps"]
        self.risky_words = policy["risky_words"]

    def request(self, method, path, body=None, timeout=None):
        if not path.startswith("/"):
            path = "/" + path
        url = self.base_url + path
        headers = {"Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json; charset=utf-8"
        elif method in ("POST", "PUT"):
            data = b"{}"
            headers["Content-Type"] = "application/json; charset=utf-8"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        wait = self.timeout if timeout is None else timeout
        try:
            with urllib.request.urlopen(req, timeout=wait) as resp:
                raw = resp.read()
                status = getattr(resp, "status", 200)
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            status = exc.code
        except urllib.error.URLError as exc:
            reason = getattr(exc, "reason", exc)
            raise BridgeError(
                "could not reach %s: %s. Try iphone start. The phone must be unlocked."
                % (url, reason)
            )
        except (TimeoutError, socket.timeout) as exc:
            raise BridgeError("timed out talking to %s: %s" % (url, exc))
        payload = None
        if raw:
            text = raw.decode("utf-8", "replace")
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                payload = text
        return status, payload

    def call(self, method, path, body=None, timeout=None):
        status, payload = self.request(method, path, body=body, timeout=timeout)
        err = wda_error_message(payload)
        if status >= 400 or err:
            detail = err or snippet(payload)
            raise BridgeError("WDA %s %s failed (%s): %s" % (method, path, status, detail))
        return payload

    def pgrep(self, pattern):
        proc = subprocess.run(
            ["pgrep", "-fl", pattern],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        if proc.returncode not in (0, 1):
            detail = (proc.stderr or proc.stdout or "").strip()
            raise BridgeError("pgrep failed for %s: %s" % (pattern, detail or proc.returncode))
        me = {str(os.getpid()), str(os.getppid())}
        pids = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 1)
            pid = parts[0]
            cmd = parts[1] if len(parts) > 1 else ""
            first = cmd.split(None, 1)[0] if cmd else ""
            base = os.path.basename(first)
            if base == "pgrep" or pid in me:
                continue
            if not pid.isdigit():
                continue
            pids.append(pid)
        return pids

    def iproxy_pattern(self):
        port = posix_escape(int(self.device["port"]))
        udid = posix_escape(self.device["udid"])
        return "iproxy.*%s.*%s.*%s" % (port, port, udid)

    def wda_any_pattern(self):
        return "xcodebuild.*%s" % posix_escape(self.device["wda_scheme"])

    def wda_test_pattern(self):
        return "xcodebuild.*%s.*test-without-building" % posix_escape(self.device["wda_scheme"])

    def spawn_background(self, argv, log_path, cwd):
        log_path = os.path.expanduser(log_path)
        directory = os.path.dirname(log_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        handle = open(log_path, "a", encoding="utf-8")
        try:
            handle.write("===== %s start =====\n" % now_et_iso())
            handle.flush()
            proc = subprocess.Popen(
                ["/usr/bin/nohup"] + list(argv),
                stdout=handle,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                cwd=cwd,
                start_new_session=True,
                close_fds=True,
            )
        finally:
            handle.close()
        return proc.pid

    def try_status(self):
        try:
            return self.call("GET", "/status", timeout=min(self.timeout, 5.0))
        except BridgeError as exc:
            sys.stderr.write("note: /status is not ready yet: %s\n" % exc)
            return None

    def print_status_report(self, payload, reach_error=None):
        if payload is None:
            ready, ios, ip_addr, status_sid = False, "unknown", "unknown", None
        else:
            ready, ios, ip_addr, status_sid = parse_status(payload)
        print("ready: %s" % ("true" if ready else "false"))
        print("ios: %s" % ios)
        print("ip: %s" % ip_addr)
        if reach_error:
            print("reach: %s" % reach_error)
        iproxy_pids = None
        wda_pids = None
        try:
            iproxy_pids = self.pgrep(self.iproxy_pattern())
            wda_pids = self.pgrep(self.wda_any_pattern())
        except BridgeError as exc:
            print("iproxy: unknown")
            print("xcodebuild_wda: unknown")
            print("process_check: %s" % exc)
        if iproxy_pids is not None:
            print("iproxy: %s" % format_pids(iproxy_pids))
        if wda_pids is not None:
            print("xcodebuild_wda: %s" % format_pids(wda_pids))
        file_sid = read_session()
        if file_sid:
            print("session: %s" % file_sid)
        elif status_sid:
            print("session: %s" % status_sid)
        else:
            print("session: none")
        if file_sid and status_sid and file_sid != status_sid:
            print("status_session: %s" % status_sid)

    def session_valid(self, sid):
        status, payload = self.request("GET", "/session/%s" % url_quote(sid))
        if status >= 400:
            return False
        if wda_error_message(payload):
            return False
        return True

    def status_session_id(self):
        try:
            payload = self.call("GET", "/status")
        except BridgeError:
            return None
        return extract_session_id(payload)

    def create_session(self):
        bodies = [
            {"capabilities": {"alwaysMatch": {}}},
            {"desiredCapabilities": {}},
        ]
        errors = []
        for body in bodies:
            status, payload = self.request("POST", "/session", body)
            err = wda_error_message(payload)
            sid = extract_session_id(payload) if status < 400 and not err else None
            if sid:
                write_session(sid)
                return sid
            errors.append(err or "HTTP %s" % status)
        raise BridgeError(
            "could not create a WDA session (no app is launched): %s" % "; ".join(errors)
        )

    def ensure_session(self):
        sid = read_session()
        if sid and self.session_valid(sid):
            return sid
        sid = self.status_session_id()
        if sid and self.session_valid(sid):
            write_session(sid)
            return sid
        return self.create_session()

    def fetch_source(self, sid):
        errors = []
        paths = [
            "/session/%s/source?format=json" % url_quote(sid),
            "/source?format=json",
        ]
        for path in paths:
            try:
                payload = self.call("GET", path)
                return unwrap_source(payload)
            except BridgeError as exc:
                errors.append("%s: %s" % (path, exc))
            except json.JSONDecodeError as exc:
                errors.append("%s: %s" % (path, exc))
        raise BridgeError("could not read element source. %s" % " | ".join(errors))

    def element_attr(self, sid, eid, name):
        path = "/session/%s/element/%s/attribute/%s" % (
            url_quote(sid),
            url_quote(eid),
            url_quote(name),
        )
        status, payload = self.request("GET", path)
        if status == 404:
            return None
        if status >= 400:
            err = wda_error_message(payload) or "HTTP %s" % status
            raise BridgeError("could not read element %s: %s" % (name, err))
        if wda_error_message(payload):
            return None
        if isinstance(payload, dict):
            return payload.get("value")
        return None

    def first_visible_element(self, sid, elements):
        fallback = None
        for item in elements:
            eid = element_id(item)
            if not eid:
                continue
            visible = self.element_attr(sid, eid, "visible")
            if visible is None:
                displayed = self.element_attr(sid, eid, "displayed")
                if displayed is not None:
                    visible = displayed
            label = self.element_attr(sid, eid, "label")
            name = self.element_attr(sid, eid, "name")
            label = "" if label is None else str(label)
            name = "" if name is None else str(name)
            record = (eid, label, name)
            if visible is None:
                if fallback is None:
                    fallback = record
                continue
            if truthy(visible):
                return record
        return fallback

    def focused_type(self, sid):
        try:
            payload = self.call("GET", "/session/%s/element/active" % url_quote(sid))
        except BridgeError:
            return None
        eid = element_id(payload)
        if not eid:
            return None
        try:
            value = self.element_attr(sid, eid, "type")
        except BridgeError:
            return None
        if value is None:
            return None
        return str(value)

    def ensure_iproxy(self):
        pids = self.pgrep(self.iproxy_pattern())
        if pids:
            print("iproxy already running (%s)" % ", ".join(pids), flush=True)
            return
        binary = os.path.expanduser(str(self.device["iproxy_bin"]))
        if not os.path.isfile(binary) or not os.access(binary, os.X_OK):
            raise BridgeError("iproxy is not executable at %s" % binary)
        port = str(int(self.device["port"]))
        argv = [binary, port, port, "-u", str(self.device["udid"])]
        pid = self.spawn_background(argv, self.device["iproxy_log"], cwd="/")
        print(
            "started iproxy pid %s, log %s"
            % (pid, os.path.expanduser(self.device["iproxy_log"])),
            flush=True,
        )

    def ensure_wda_test(self):
        test_pids = self.pgrep(self.wda_test_pattern())
        if test_pids:
            print(
                "WDA test-without-building already running (%s)" % ", ".join(test_pids),
                flush=True,
            )
            return
        any_pids = self.pgrep(self.wda_any_pattern())
        if any_pids:
            print(
                "A WebDriverAgent xcodebuild is already running (%s). "
                "Not starting another one. This command never kills existing processes."
                % ", ".join(any_pids),
                flush=True,
            )
            return
        wda_dir = os.path.expanduser(str(self.device["wda_dir"]))
        if not os.path.isdir(wda_dir):
            raise BridgeError("WebDriverAgent directory is missing: %s" % wda_dir)
        if shutil.which("xcodebuild") is None:
            raise BridgeError("xcodebuild is not on PATH")
        argv = [
            "xcodebuild",
            "-project", str(self.device["wda_project"]),
            "-scheme", str(self.device["wda_scheme"]),
            "-destination", "id=%s" % self.device["udid"],
            "-derivedDataPath", os.path.expanduser(str(self.device["derived_data"])),
            "-allowProvisioningUpdates",
            "DEVELOPMENT_TEAM=%s" % self.device["team_id"],
            "PRODUCT_BUNDLE_IDENTIFIER=%s" % self.device["wda_bundle_id"],
            "CODE_SIGN_STYLE=%s" % (self.device.get("code_sign_style") or "Automatic"),
            "test-without-building",
        ]
        pid = self.spawn_background(argv, self.device["wda_run_log"], cwd=wda_dir)
        print(
            "started WDA xcodebuild test-without-building pid %s, log %s"
            % (pid, os.path.expanduser(self.device["wda_run_log"])),
            flush=True,
        )

    def wait_until_ready(self, seconds):
        deadline = time.monotonic() + seconds
        next_note = time.monotonic() + 10
        poll_timeout = min(self.timeout, 5.0)
        sys.stderr.write(
            "waiting up to %d seconds for WDA /status. Phone must be unlocked.\n" % seconds
        )
        while True:
            try:
                payload = self.call("GET", "/status", timeout=poll_timeout)
            except BridgeError:
                payload = None
            if payload is not None and status_is_ready(payload):
                return payload
            now = time.monotonic()
            if now >= deadline:
                return None
            if now >= next_note:
                sys.stderr.write("still waiting for WDA.\n")
                next_note = now + 10
            time.sleep(min(2.0, max(0.0, deadline - now)))

    def cmd_status(self, _args):
        try:
            payload = self.call("GET", "/status")
        except BridgeError as exc:
            self.print_status_report(None, reach_error=str(exc))
            return None
        self.print_status_report(payload)
        return None

    def cmd_start(self, _args):
        print("Phone must be unlocked.", flush=True)
        print("This command does not kill existing processes.", flush=True)
        payload = self.try_status()
        if payload is not None and status_is_ready(payload):
            print("WDA is already ready. Not starting anything.", flush=True)
            self.print_status_report(payload)
            return None
        self.ensure_iproxy()
        time.sleep(1.0)
        payload = self.try_status()
        if payload is not None and status_is_ready(payload):
            print("WDA is ready.", flush=True)
            self.print_status_report(payload)
            return None
        self.ensure_wda_test()
        payload = self.wait_until_ready(90)
        if payload is None:
            raise BridgeError(
                "WDA /status was not ready after 90 seconds. Phone must be unlocked. "
                "Logs: %s and %s. This command does not kill existing processes."
                % (
                    os.path.expanduser(self.device["iproxy_log"]),
                    os.path.expanduser(self.device["wda_run_log"]),
                )
            )
        print("WDA is ready.", flush=True)
        self.print_status_report(payload)
        return None

    def cmd_screenshot(self, args):
        payload = self.call("GET", "/screenshot")
        value = payload.get("value") if isinstance(payload, dict) else payload
        raw = decode_png_b64(value)
        if args.out:
            path = os.path.abspath(os.path.expanduser(args.out))
        else:
            directory = os.path.expanduser(str(self.device["shots_dir"]))
            os.makedirs(directory, exist_ok=True)
            stamp = shot_stamp()
            path = os.path.join(directory, "shot-%s.png" % stamp)
            suffix = 2
            while os.path.exists(path):
                if suffix > 1000:
                    raise BridgeError("could not find a free screenshot path in %s" % directory)
                path = os.path.join(directory, "shot-%s-%d.png" % (stamp, suffix))
                suffix += 1
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(raw)
        print(path)
        return path

    def cmd_tree(self, args):
        sid = self.ensure_session()
        tree = self.fetch_source(sid)
        rows = collect_rows(tree)
        shown = rows[: args.max]
        if args.json:
            print(json.dumps(shown, indent=2, ensure_ascii=False))
        else:
            for row in shown:
                print(format_row(row))
        if len(rows) > args.max:
            sys.stderr.write(
                "note: showing %d of %d elements. Raise --max to see more.\n" % (args.max, len(rows))
            )
        return None

    def cmd_tap(self, args):
        x = float(args.x)
        y = float(args.y)
        sid = self.ensure_session()
        tree = None
        lookup_error = None
        try:
            tree = self.fetch_source(sid)
        except Exception as exc:
            # Source failures and unexpected lookup errors must not fall through to a tap.
            lookup_error = exc
        _texts, note = tap_guard(
            tree, x, y, self.risky_words, args.approved, lookup_error=lookup_error
        )
        if note:
            sys.stderr.write("note: %s\n" % note)
        body = {"x": json_num(x), "y": json_num(y)}
        try:
            self.call("POST", "/session/%s/wda/tap" % url_quote(sid), body)
            how = "wda/tap"
        except BridgeError as first_error:
            try:
                self.call("POST", "/session/%s/actions" % url_quote(sid), w3c_tap_body(x, y))
                how = "W3C actions"
            except BridgeError as second_error:
                raise BridgeError(
                    "tap failed. wda/tap: %s. W3C actions: %s" % (first_error, second_error)
                )
        print("tapped %s,%s via %s" % (fmt_num(x), fmt_num(y), how))
        return None

    def cmd_tap_label(self, args):
        text = args.text
        if not isinstance(text, str) or not text.strip():
            raise BridgeError("tap-label text is empty")
        if not args.approved:
            word = matching_risky_word(text, self.risky_words)
            if word:
                raise Blocked(
                    "refusing to tap label %s: it matches risky word '%s'. "
                    "Pass --approved only after the owner says yes."
                    % (json.dumps(text), word)
                )
        sid = self.ensure_session()
        predicate = predicate_for(text, args.exact)
        found = None
        errors = []
        for strategy in ("predicate string", "-ios predicate string"):
            try:
                payload = self.call(
                    "POST",
                    "/session/%s/elements" % url_quote(sid),
                    {"using": strategy, "value": predicate},
                )
            except BridgeError as exc:
                errors.append(str(exc))
                continue
            if isinstance(payload, dict) and "value" in payload:
                found = payload.get("value") or []
                break
            errors.append("unexpected search response")
        if found is None:
            raise BridgeError("element search failed: %s" % "; ".join(errors))
        if isinstance(found, dict):
            found = [found]
        if not isinstance(found, list):
            raise BridgeError("element search returned an unexpected payload")
        chosen = self.first_visible_element(sid, found)
        if not chosen:
            raise BridgeError("no visible element matched %s" % json.dumps(text))
        eid, label, name = chosen
        if not args.approved:
            word = matching_risky_word(label, self.risky_words) or matching_risky_word(
                name, self.risky_words
            )
            if word:
                raise Blocked(
                    "refusing to tap matched element label %s name %s: risky word '%s'. "
                    "Pass --approved only after the owner says yes."
                    % (json.dumps(label), json.dumps(name), word)
                )
        self.call(
            "POST",
            "/session/%s/element/%s/click" % (url_quote(sid), url_quote(eid)),
            {},
        )
        print("clicked %s" % json.dumps(label or name or text, ensure_ascii=False))
        return None

    def cmd_type(self, args):
        text = args.text
        if not isinstance(text, str):
            raise BridgeError("type text must be a string")
        if not args.approved:
            reasons = []
            word = matching_risky_word(text, self.risky_words)
            if word:
                reasons.append("text matches risky word '%s'" % word)
            if has_long_digit_run(text):
                reasons.append("text contains 13 or more consecutive digits")
            if reasons:
                raise Blocked(
                    "refusing to type: %s. Pass --approved only after the owner says yes."
                    % "; ".join(reasons)
                )
        sid = self.ensure_session()
        if not args.approved:
            kind = self.focused_type(sid)
            if kind is None:
                sys.stderr.write(
                    "note: could not read the focused element. Continuing with the text checks.\n"
                )
            elif "SecureTextField" in kind:
                raise Blocked(
                    "refusing to type: the focused element is a secure text field. "
                    "Pass --approved only after the owner says yes."
                )
        self.call(
            "POST",
            "/session/%s/wda/keys" % url_quote(sid),
            {"value": list(text)},
        )
        print("typed %d characters" % len(text))
        return None

    def cmd_swipe(self, args):
        body = {
            "fromX": json_num(args.x1),
            "fromY": json_num(args.y1),
            "toX": json_num(args.x2),
            "toY": json_num(args.y2),
            "duration": json_num(args.duration),
        }
        sid = self.ensure_session()
        self.call("POST", "/session/%s/wda/dragfromtoforduration" % url_quote(sid), body)
        print(
            "swiped %s,%s to %s,%s duration=%s"
            % (
                fmt_num(args.x1),
                fmt_num(args.y1),
                fmt_num(args.x2),
                fmt_num(args.y2),
                fmt_num(args.duration),
            )
        )
        return None

    def cmd_home(self, _args):
        try:
            self.call("POST", "/wda/homescreen", {})
        except BridgeError as first_error:
            try:
                sid = self.ensure_session()
                self.call("POST", "/session/%s/wda/homescreen" % url_quote(sid), {})
            except BridgeError as second_error:
                raise BridgeError(
                    "home failed. /wda/homescreen: %s. session route: %s"
                    % (first_error, second_error)
                )
        print("pressed home")
        return None

    def cmd_launch(self, args):
        bundle = args.bundle
        if not isinstance(bundle, str) or not bundle.strip():
            raise BridgeError("bundle id is empty")
        if not args.force:
            reason = launch_block_reason(bundle, self.allowed_apps)
            if reason:
                raise Blocked(
                    "refusing to launch %s: %s Use --force only when you intend to override the allowlist."
                    % (bundle, reason)
                )
        sid = self.ensure_session()
        payload = self.call(
            "POST",
            "/session/%s/wda/apps/launch" % url_quote(sid),
            {"bundleId": bundle},
        )
        if isinstance(payload, dict) and payload.get("value") is False:
            raise BridgeError("WDA did not launch %s" % bundle)
        print("launched %s" % bundle)
        return None

    def cmd_terminate(self, args):
        bundle = args.bundle
        if not isinstance(bundle, str) or not bundle.strip():
            raise BridgeError("bundle id is empty")
        sid = self.ensure_session()
        payload = self.call(
            "POST",
            "/session/%s/wda/apps/terminate" % url_quote(sid),
            {"bundleId": bundle},
        )
        if isinstance(payload, dict) and payload.get("value") is False:
            raise BridgeError("WDA did not terminate %s" % bundle)
        print("terminated %s" % bundle)
        return None

    def cmd_lock_check(self, _args):
        payload = self.call("GET", "/wda/locked")
        locked = parse_locked(payload)
        print("locked: %s" % ("true" if locked else "false"))
        return None

    def cmd_apps(self, _args):
        apps = self.allowed_apps
        if not apps:
            print("allowlist is empty")
            return None
        width = max(len(str(key)) for key in apps)
        for bundle, name in apps.items():
            print("%-*s  %s" % (width, bundle, name))
        return None

    def cmd_session(self, _args):
        sid = self.ensure_session()
        print("session: %s" % sid)
        return None

    def dispatch(self, args):
        name = args.command
        if name == "status":
            return self.cmd_status(args)
        if name == "start":
            return self.cmd_start(args)
        if name == "screenshot":
            return self.cmd_screenshot(args)
        if name == "tree":
            return self.cmd_tree(args)
        if name == "tap":
            return self.cmd_tap(args)
        if name == "tap-label":
            return self.cmd_tap_label(args)
        if name == "type":
            return self.cmd_type(args)
        if name == "swipe":
            return self.cmd_swipe(args)
        if name == "home":
            return self.cmd_home(args)
        if name == "launch":
            return self.cmd_launch(args)
        if name == "terminate":
            return self.cmd_terminate(args)
        if name in ("lock-check", "unlock-check"):
            return self.cmd_lock_check(args)
        if name == "apps":
            return self.cmd_apps(args)
        if name == "session":
            return self.cmd_session(args)
        raise BridgeError("unknown command %s" % name)


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    argv = move_global_flags(list(argv))
    parser = build_parser()
    args = parser.parse_args(argv)
    code = 0
    result = "ok"
    screenshot = None
    policy = None
    try:
        policy = load_policy()
        url = args.url or policy["device"].get("default_url") or (
            "http://127.0.0.1:%s" % policy["device"]["port"]
        )
        client = Client(url, args.timeout, policy)
        screenshot = client.dispatch(args)
    except Blocked as exc:
        code = 3
        result = "blocked"
        sys.stderr.write("blocked: %s\n" % exc)
    except BridgeError as exc:
        code = exc.code or 1
        result = "error"
        sys.stderr.write("error: %s\n" % exc)
    except Exception as exc:
        code = 1
        result = "error"
        sys.stderr.write("error: %s: %s\n" % (exc.__class__.__name__, exc))
    log_ok = True
    try:
        if policy is None:
            policy = try_load_policy()
        append_jsonl(
            actions_log_path(policy),
            build_record(args.command, args_for_log(args), result, screenshot),
        )
    except Exception as exc:
        log_ok = False
        sys.stderr.write("error: could not write action log: %s\n" % exc)
    if not log_ok and code == 0:
        code = 1
    sys.exit(code)


if __name__ == "__main__":
    main()
