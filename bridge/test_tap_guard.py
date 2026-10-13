"""Offline tests for tap_guard and cmd_tap. No phone and no network."""

import argparse
import importlib.util
import io
import json
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), "iphone.py")
_SPEC = importlib.util.spec_from_file_location("iphone_bridge", _PATH)
iphone = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(iphone)

RISKY = ["send", "buy", "pay", "submit", "delete", "post"]


def rect(x, y, w, h):
    return {"x": x, "y": y, "width": w, "height": h}


def element(label=None, name=None, x=0, y=0, w=100, h=40, children=None, visible=True):
    node = {
        "type": "XCUIElementTypeButton",
        "rect": rect(x, y, w, h),
        "visible": visible,
        "children": children or [],
    }
    if label is not None:
        node["label"] = label
    if name is not None:
        node["name"] = name
    return node


def assert_no_tap_request(test, recorded):
    test.assertTrue(recorded, "source lookup should have been attempted")
    for method, path, body in recorded:
        test.assertNotIn("/wda/tap", path)
        test.assertNotRegex(path, r"/actions($|\?)")
        if str(method).upper() == "POST":
            test.fail("unexpected POST %s body=%r" % (path, body))


class TapGuardTests(unittest.TestCase):
    def test_module_imports_without_running_main(self):
        self.assertNotEqual(iphone.__name__, "__main__")
        self.assertTrue(callable(iphone.tap_guard))
        self.assertTrue(callable(iphone.main))

    def test_lookup_error_not_approved_blocks(self):
        with self.assertRaises(iphone.Blocked) as ctx:
            iphone.tap_guard(
                None, 10, 20, RISKY, False, lookup_error="source fetch failed"
            )
        self.assertEqual(ctx.exception.code, 3)
        message = str(ctx.exception)
        self.assertIn("refusing to tap 10,20", message)
        self.assertIn("could not read what element is at that point", message)
        self.assertIn("source fetch failed", message)

    def test_lookup_error_approved_returns_note(self):
        texts, note = iphone.tap_guard(
            None, 10, 20, RISKY, True, lookup_error=iphone.BridgeError("source fetch failed")
        )
        self.assertEqual(texts, [])
        self.assertIsInstance(note, str)
        self.assertIn("could not read", note)
        self.assertIn("source fetch failed", note)

    def test_point_outside_every_frame_blocks(self):
        tree = element(label="Wi-Fi", x=0, y=0, w=10, h=10)
        with self.assertRaises(iphone.Blocked) as ctx:
            iphone.tap_guard(tree, 200, 420, RISKY, False)
        self.assertEqual(ctx.exception.code, 3)
        self.assertIn("unknown element", str(ctx.exception))

    def test_unlabeled_element_without_labeled_ancestor_blocks(self):
        tree = element(
            x=0, y=0, w=400, h=800,
            children=[element(x=10, y=10, w=40, h=40, label="", name="")],
        )
        with self.assertRaises(iphone.Blocked) as ctx:
            iphone.tap_guard(tree, 20, 20, RISKY, False)
        self.assertEqual(ctx.exception.code, 3)
        self.assertIn("unknown element", str(ctx.exception))

    def test_unlabeled_child_of_safe_parent_is_allowed(self):
        tree = element(
            label="Bluetooth",
            x=0, y=0, w=400, h=800,
            children=[element(x=20, y=30, w=40, h=40)],
        )
        texts, note = iphone.tap_guard(tree, 25, 40, RISKY, False)
        self.assertIsNone(note)
        self.assertEqual(texts, ["Bluetooth"])

    def test_safe_labeled_element_is_allowed(self):
        tree = element(label="Wi-Fi", x=100, y=200, w=80, h=44)
        texts, note = iphone.tap_guard(tree, 120, 220, RISKY, False)
        self.assertIsNone(note)
        self.assertEqual(texts, ["Wi-Fi"])

    def test_send_is_blocked_unless_approved(self):
        tree = element(label="Send", x=0, y=0, w=100, h=40)
        with self.assertRaises(iphone.Blocked) as ctx:
            iphone.tap_guard(tree, 10, 10, RISKY, False)
        self.assertEqual(ctx.exception.code, 3)
        self.assertIn("risky word 'send'", str(ctx.exception))

        texts, note = iphone.tap_guard(tree, 10, 10, RISKY, True)
        self.assertEqual(texts, ["Send"])
        self.assertIsInstance(note, str)
        self.assertIn("send", note.lower())

    def test_unlabeled_icon_inside_send_is_blocked(self):
        tree = element(
            label="Send",
            x=0, y=0, w=120, h=50,
            children=[element(x=10, y=10, w=20, h=20)],
        )
        with self.assertRaises(iphone.Blocked) as ctx:
            iphone.tap_guard(tree, 15, 15, RISKY, False)
        self.assertEqual(ctx.exception.code, 3)
        self.assertIn("risky word 'send'", str(ctx.exception))

    def test_malformed_tree_blocks_instead_of_crashing(self):
        cases = [
            None,
            {"rect": {"x": "garbage", "y": "nope", "width": "bad", "height": "zz"}, "label": "Send"},
            {"rect": [0, 0, 10, 10], "label": "Wi-Fi"},
            {"rect": {"x": object(), "y": object(), "width": object(), "height": object()}, "label": "Wi-Fi"},
        ]
        for tree in cases:
            with self.subTest(tree=type(tree).__name__):
                with self.assertRaises(iphone.Blocked) as ctx:
                    iphone.tap_guard(tree, 5, 5, RISKY, False)
                self.assertEqual(ctx.exception.code, 3)

    def test_hit_lookup_exceptions_are_could_not_read(self):
        tree = element(label="Wi-Fi")
        for exc_type in (TypeError, KeyError, ValueError):
            with self.subTest(exc=exc_type.__name__):
                def boom(_tree, _x, _y, exc_type=exc_type):
                    raise exc_type("weird tree")

                with mock.patch.object(iphone, "hit_texts", side_effect=boom):
                    with self.assertRaises(iphone.Blocked) as ctx:
                        iphone.tap_guard(tree, 10, 10, RISKY, False)
                    self.assertEqual(ctx.exception.code, 3)
                    self.assertIn("could not read", str(ctx.exception))
                    self.assertIn("weird tree", str(ctx.exception))

                    texts, note = iphone.tap_guard(tree, 10, 10, RISKY, True)
                self.assertEqual(texts, [])
                self.assertIn("weird tree", note)
                self.assertIn("could not read", note)


class CmdTapTests(unittest.TestCase):
    def make_client(self):
        return iphone.Client(
            "http://127.0.0.1:9",
            0.2,
            {"device": {}, "allowed_apps": {}, "risky_words": list(RISKY)},
        )

    def run_tap(self, client, args, fake_call):
        with mock.patch.object(
            iphone.urllib.request, "urlopen", side_effect=AssertionError("network used")
        ):
            with mock.patch.object(client, "ensure_session", return_value="fake-session"):
                with mock.patch.object(client, "call", side_effect=fake_call):
                    return client.cmd_tap(args)

    def test_cmd_tap_failed_source_sends_no_tap(self):
        failures = [
            iphone.BridgeError("simulated source failure"),
            json.JSONDecodeError("bad json", "doc", 0),
            TypeError("weird tree"),
            KeyError("frame"),
            ValueError("bad frame"),
        ]
        for failure in failures:
            with self.subTest(exc=failure.__class__.__name__):
                recorded = []

                def fake_call(method, path, body=None, timeout=None, failure=failure):
                    recorded.append((method, path, body))
                    raise failure

                client = self.make_client()
                args = argparse.Namespace(x=12, y=34, approved=False)
                with self.assertRaises(iphone.Blocked) as ctx:
                    self.run_tap(client, args, fake_call)
                self.assertEqual(ctx.exception.code, 3)
                message = str(ctx.exception)
                self.assertIn("could not read", message)
                self.assertIn("12,34", message)
                assert_no_tap_request(self, recorded)

    def test_cmd_tap_risky_tree_sends_no_tap(self):
        recorded = []
        payload = {
            "value": element(label="Send", x=0, y=0, w=100, h=40),
        }

        def fake_call(method, path, body=None, timeout=None):
            recorded.append((method, path, body))
            if method == "GET" and "source" in path:
                return payload
            raise iphone.BridgeError("tap should not have been sent")

        client = self.make_client()
        args = argparse.Namespace(x=10, y=10, approved=False)
        with self.assertRaises(iphone.Blocked) as ctx:
            self.run_tap(client, args, fake_call)
        self.assertEqual(ctx.exception.code, 3)
        self.assertIn("risky word 'send'", str(ctx.exception))
        assert_no_tap_request(self, recorded)

    def test_cmd_tap_approved_source_failure_notes_then_taps(self):
        recorded = []

        def fake_call(method, path, body=None, timeout=None):
            recorded.append((method, path, body))
            if "source" in path:
                raise iphone.BridgeError("simulated source failure")
            if method == "POST" and "/wda/tap" in path:
                return {"value": None}
            raise iphone.BridgeError("unexpected %s %s" % (method, path))

        client = self.make_client()
        args = argparse.Namespace(x=3, y=4, approved=True)
        stderr = io.StringIO()
        with redirect_stderr(stderr), redirect_stdout(io.StringIO()):
            self.run_tap(client, args, fake_call)
        note = stderr.getvalue()
        self.assertIn("simulated source failure", note)
        self.assertIn("could not read", note)
        posts = [item for item in recorded if item[0] == "POST"]
        self.assertEqual(len(posts), 1)
        self.assertIn("/wda/tap", posts[0][1])
        self.assertNotIn("/actions", posts[0][1])
        self.assertEqual(posts[0][2], {"x": 3, "y": 4})
        first_post = next(index for index, item in enumerate(recorded) if item[0] == "POST")
        self.assertTrue(all(item[0] == "GET" for item in recorded[:first_post]))


if __name__ == "__main__":
    unittest.main()
