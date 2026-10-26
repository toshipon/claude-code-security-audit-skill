"""Exercise the public CLI in disposable projects; no installed scanners required."""

import json
import os
import queue
import signal
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from pathlib import Path

SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "plugins/security-audit/skills/security-audit/scripts/audit_workflow.py"
)


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.root = self.home / "project"
        self.root.mkdir()
        self.rules = self.write_json(
            "rules.json",
            {
                "rules": [
                    {
                        "id": "unsafe-eval",
                        "pattern": r"eval\(",
                        "include": ["*.py"],
                        "message": "Review dynamic evaluation",
                        "level": "warning",
                    }
                ]
            },
        )

    def write_json(self, name, value):
        path = self.home / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def cli(self, *args, code=0):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), *map(str, args)],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(result.returncode, code, result.stderr)
        if code == 2:
            self.assertEqual(result.stdout, "")
            self.assertNotIn("Traceback", result.stderr)
            return result
        return json.loads(result.stdout)

    def scan(self, code=0):
        return self.cli("scan", "--root", self.root, "--rules", self.rules, code=code)

    def sarif(self, results=None, tool="Semgrep", **run_extra):
        run = {
            "tool": {
                "driver": {
                    "name": tool,
                    "rules": [
                        {
                            "id": "unsafe-eval",
                            "defaultConfiguration": {"level": "warning"},
                        }
                    ],
                }
            },
            "results": results
            if results is not None
            else [
                {
                    "ruleId": "unsafe-eval",
                    "message": {"text": "SECRET_CANARY_8379"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/app%20file.py"},
                                "region": {"startLine": 3},
                            }
                        }
                    ],
                }
            ],
        }
        run.update(run_extra)
        return {"version": "2.1.0", "runs": [run]}

    def imported(self, data, code=0):
        return self.cli(
            "import-sarif",
            "--root",
            self.root,
            "--input",
            self.write_json("scan.sarif", data),
            code=code,
        )

    def compare(self, baseline, current, *extra, code=0):
        return self.cli(
            "monitor",
            "--baseline",
            self.write_json("baseline.json", baseline),
            "--current",
            self.write_json("current.json", current),
            *extra,
            code=code,
        )

    def test_scan_reports_line_without_leaking_source(self):
        (self.root / "app.py").write_text("# comment\neval('SECRET_CANARY_8379')\n")
        result = self.scan()
        self.assertEqual(result["schema_version"], 1)
        (finding,) = result["findings"]
        self.assertEqual(
            (finding["path"], finding["line"], finding["rule_id"]),
            ("app.py", 2, "unsafe-eval"),
        )
        self.assertEqual(finding["scanner_level"], "warning")
        self.assertEqual(finding["cvss_status"], "Unscored")
        self.assertNotIn("SECRET_CANARY_8379", json.dumps(result))
        self.assertEqual(self.scan(), result)

    def test_scan_includes_nested_files_and_excludes_git_and_symlinks(self):
        (self.root / "src").mkdir()
        (self.root / "src/app.py").write_text("eval('input')\n")
        (self.root / ".git").mkdir()
        (self.root / ".git/hidden.py").write_text("eval('hidden')\n")
        outside = self.home / "outside.py"
        outside.write_text("eval('outside')\n")
        (self.root / "linked.py").symlink_to(outside)
        (self.root / "linked-dir").symlink_to(self.home, target_is_directory=True)
        self.assertEqual([f["path"] for f in self.scan()["findings"]], ["src/app.py"])

    def test_scan_clean_project(self):
        (self.root / "app.py").write_text("print('hello')\n")
        self.assertEqual(self.scan()["findings"], [])

    def test_plain_clone_install_can_run_the_same_helper(self):
        alias = Path(__file__).resolve().parents[1] / "scripts/audit_workflow.py"
        result = subprocess.run(
            [
                sys.executable,
                str(alias),
                "scan",
                "--root",
                str(self.root),
                "--rules",
                str(self.rules),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), self.scan())

    def test_rules_reject_invalid_regex_duplicate_ids_and_commands(self):
        original = json.loads(self.rules.read_text())
        for variant in ("regex", "duplicate", "command"):
            with self.subTest(variant=variant):
                rules = json.loads(json.dumps(original))
                if variant == "regex":
                    rules["rules"][0]["pattern"] = "["
                elif variant == "duplicate":
                    rules["rules"] *= 2
                else:
                    rules["rules"][0]["command"] = "touch should-not-exist"
                self.rules.write_text(json.dumps(rules))
                self.scan(code=2)
        self.assertFalse((self.root / "should-not-exist").exists())

    def test_scan_rejects_incomplete_oversized_or_non_utf8_input(self):
        path = self.root / "app.py"
        for content in (b"\xff", b"x" * (1024 * 1024 + 1)):
            with self.subTest(size=len(content)):
                path.write_bytes(content)
                self.scan(code=2)

    def test_sarif_semgrep_and_codeql_are_unscored_and_redacted(self):
        data = self.sarif()
        data["runs"] += self.sarif(tool="CodeQL")["runs"]
        result = self.imported(data)
        self.assertEqual(len(result["findings"]), 2)
        self.assertEqual({f["path"] for f in result["findings"]}, {"src/app file.py"})
        self.assertEqual({f["cvss_status"] for f in result["findings"]}, {"Unscored"})
        self.assertNotIn("SECRET_CANARY_8379", json.dumps(result))

    def test_sarif_rule_index_and_default_level(self):
        data = self.sarif()
        result = data["runs"][0]["results"][0]
        del result["ruleId"]
        result["ruleIndex"] = 0
        (finding,) = self.imported(data)["findings"]
        self.assertEqual(finding["rule_id"], "unsafe-eval")
        self.assertEqual(finding["scanner_level"], "warning")

    def test_sarif_rejects_paths_outside_root(self):
        for uri in (
            "../secret.py",
            "%2e%2e/secret.py",
            "file:///etc/passwd",
            "https://evil.example/app.py",
        ):
            with self.subTest(uri=uri):
                data = self.sarif()
                data["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
                    "artifactLocation"
                ]["uri"] = uri
                self.imported(data, code=2)

    def test_sarif_rejects_failed_scans_and_missing_locations(self):
        for data in (
            self.sarif(invocations=[{"executionSuccessful": False}]),
            self.sarif(results=[{"ruleId": "r", "message": {"text": "bad"}}]),
            {"version": "2.1.0", "runs": []},
            {"version": "1.0", "runs": []},
        ):
            with self.subTest(data=data):
                self.imported(data, code=2)

    def test_sarif_empty_success_is_clean(self):
        self.assertEqual(self.imported(self.sarif(results=[]))["findings"], [])

    def test_sarif_incomplete_run_is_not_clean(self):
        data = self.sarif()
        del data["runs"][0]["results"]
        self.imported(data, code=2)

    def test_sarif_artifact_indices_and_absolute_uri_base(self):
        data = self.sarif()
        run = data["runs"][0]
        run["originalUriBaseIds"] = {"SRCROOT": {"uri": self.root.as_uri() + "/"}}
        run["artifacts"] = [{"location": {"uri": "src/app.py", "uriBaseId": "SRCROOT"}}]
        run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"] = {
            "index": 0
        }
        self.assertEqual(self.imported(data)["findings"][0]["path"], "src/app.py")

    def test_real_semgrep_srcroot_without_base_definition(self):
        # Semgrep 1.182.1 emits %SRCROOT% without originalUriBaseIds.
        for uri in (str(self.root / "app.py"), "app.py"):
            with self.subTest(uri=uri):
                data = self.sarif(
                    invocations=[
                        {
                            "executionSuccessful": True,
                            "toolExecutionNotifications": [],
                        }
                    ]
                )
                physical = data["runs"][0]["results"][0]["locations"][0][
                    "physicalLocation"
                ]
                physical["artifactLocation"] = {"uri": uri, "uriBaseId": "%SRCROOT%"}
                self.assertEqual(self.imported(data)["findings"][0]["path"], "app.py")

    def test_sarif_rejects_undefined_relative_base_and_srcroot_escape(self):
        for uri, base in (("app.py", "UNKNOWN"), ("../secret.py", "%SRCROOT%")):
            with self.subTest(uri=uri, base=base):
                data = self.sarif()
                physical = data["runs"][0]["results"][0]["locations"][0][
                    "physicalLocation"
                ]
                physical["artifactLocation"] = {"uri": uri, "uriBaseId": base}
                self.imported(data, code=2)

    def test_sarif_error_notifications_are_not_clean(self):
        data = self.sarif(
            results=[],
            invocations=[
                {
                    "executionSuccessful": True,
                    "toolExecutionNotifications": [
                        {"level": "error", "message": {"text": "SECRET_CANARY_8379"}}
                    ],
                }
            ],
        )
        result = self.imported(data, code=2)
        self.assertNotIn("SECRET_CANARY_8379", result.stderr)

    def test_monitor_rejects_changed_scanner_rules(self):
        data = self.sarif()
        before = self.imported(data)
        data["runs"][0]["tool"]["driver"]["rules"].append({"id": "different-query"})
        after = self.imported(data)
        self.compare(before, after, code=2)

    def test_snapshot_order_does_not_change_monitor_results(self):
        (self.root / "app.py").write_text("eval('one')\neval('two')\n")
        before = self.scan()
        after = {**before, "findings": list(reversed(before["findings"]))}
        result = self.compare(before, after)
        self.assertEqual(len(result["unchanged"]), 2)
        self.assertEqual(result["new"], [])
        self.assertEqual(result["resolved"], [])

    def test_monitor_classifies_new_resolved_and_unchanged(self):
        (self.root / "app.py").write_text("eval('old')\n")
        before = self.scan()
        (self.root / "new.py").write_text("eval('new')\n")
        after = self.scan()
        delta = self.compare(before, after, "--fail-on-new", code=1)
        self.assertEqual([f["path"] for f in delta["new"]], ["new.py"])
        self.assertEqual([f["path"] for f in delta["unchanged"]], ["app.py"])
        self.assertEqual(delta["resolved"], [])
        delta = self.compare(after, before)
        self.assertEqual([f["path"] for f in delta["resolved"]], ["new.py"])
        self.assertEqual(json.loads((self.home / "baseline.json").read_text()), after)

    def test_monitor_rejects_scope_mismatch_and_invalid_documents(self):
        before = self.scan()
        changed = json.loads(json.dumps(before))
        changed["coverage"]["rules_digest"] = "different"
        self.compare(before, changed, code=2)
        self.compare(before, {"findings": []}, code=2)
        self.compare(before, {**before, "schema_version": 99}, code=2)

    def test_monitor_rejects_duplicate_fingerprints(self):
        (self.root / "app.py").write_text("eval('old')\n")
        before = self.scan()
        duplicate = {**before, "findings": before["findings"] * 2}
        self.compare(before, duplicate, code=2)

    def git(self, *args):
        return subprocess.run(
            ["git", "-C", str(self.root), *args],
            check=True,
            capture_output=True,
            text=True,
        ).stdout

    def test_patch_check_does_not_apply_changes_and_rejects_bad_patch(self):
        self.git("init", "-q")
        (self.root / "app.py").write_text("eval('input')\n")
        self.git("add", "app.py")
        self.git(
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "fixture",
        )
        (self.root / "app.py").write_text("print('input')\n")
        patch = self.home / "fix.patch"
        patch.write_text(self.git("diff"))
        self.git("restore", "app.py")
        baseline = self.scan()
        before = self.git("status", "--porcelain")
        result = self.cli("check-patch", "--root", self.root, "--patch", patch)
        self.assertTrue(result["applicable"])
        self.assertEqual((self.root / "app.py").read_text(), "eval('input')\n")
        self.assertEqual(self.git("status", "--porcelain"), before)
        # Exercise the authorized remediation workflow separately from the
        # read-only helper: apply the reviewed patch, rescan, compare evidence.
        self.git("apply", str(patch))
        current = self.scan()
        self.assertEqual(current["findings"], [])
        delta = self.compare(baseline, current)
        self.assertEqual(len(delta["resolved"]), 1)
        self.assertEqual(delta["new"], [])
        patch.write_text("invalid patch")
        self.cli("check-patch", "--root", self.root, "--patch", patch, code=2)

    def test_missing_inputs_are_actionable_errors(self):
        self.cli("scan", "--root", self.home / "missing", "--rules", self.rules, code=2)
        self.rules.write_text("{bad-json")
        self.scan(code=2)

    def test_scan_timeout_stops_pathological_regex_without_partial_results(self):
        rules = json.loads(self.rules.read_text())
        rules["rules"][0]["pattern"] = "(a+)+$"
        self.rules.write_text(json.dumps(rules))
        (self.root / "app.py").write_text("a" * 200 + "!SECRET_CANARY_8379")
        started = time.monotonic()
        result = self.cli(
            "scan",
            "--root",
            self.root,
            "--rules",
            self.rules,
            "--timeout",
            "0.3",
            code=2,
        )
        self.assertLess(time.monotonic() - started, 6)
        self.assertIn("timeout", result.stderr.lower())
        self.assertNotIn("SECRET_CANARY_8379", result.stderr)

    def watch_command(self, baseline, *extra):
        return [
            sys.executable,
            str(SCRIPT),
            "watch",
            "--root",
            str(self.root),
            "--rules",
            str(self.rules),
            "--baseline",
            str(baseline),
            *extra,
        ]

    def start_watch(self, baseline, *extra):
        process = subprocess.Popen(
            self.watch_command(baseline, *extra),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        def cleanup():
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)

        self.addCleanup(cleanup)
        return process

    def first_event(self, process):
        lines = queue.Queue()
        reader = threading.Thread(
            target=lambda: lines.put(process.stdout.readline()), daemon=True
        )
        reader.start()
        line = lines.get(timeout=10)
        self.assertTrue(line, "watch exited before producing a completed scan")
        return json.loads(line)

    def test_watch_reports_new_findings_without_advancing_baseline(self):
        (self.root / "app.py").write_text("eval('existing')\n")
        baseline = self.write_json("baseline.json", self.scan())
        original = baseline.read_bytes()
        process = self.start_watch(baseline, "--interval", "0.3", "--iterations", "2")
        first = self.first_event(process)
        self.assertEqual(first["iteration"], 1)
        self.assertEqual(first["new"], [])
        self.assertEqual(len(first["unchanged"]), 1)
        (self.root / "new.py").write_text("eval('new')\n")
        stdout, stderr = process.communicate(timeout=10)
        self.assertEqual(process.returncode, 0, stderr)
        (second,) = [json.loads(line) for line in stdout.splitlines()]
        self.assertEqual(second["iteration"], 2)
        self.assertEqual([f["path"] for f in second["new"]], ["new.py"])
        self.assertEqual(baseline.read_bytes(), original)

    def test_watch_fail_on_new_returns_one_complete_event(self):
        baseline = self.write_json("baseline.json", self.scan())
        (self.root / "new.py").write_text("eval('new')\n")
        result = subprocess.run(
            self.watch_command(baseline, "--fail-on-new"),
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        (event,) = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(len(event["new"]), 1)

    def test_watch_failed_scan_does_not_emit_false_resolution(self):
        (self.root / "app.py").write_text("eval('existing')\n")
        baseline = self.write_json("baseline.json", self.scan())
        process = self.start_watch(baseline, "--interval", "0.3", "--iterations", "2")
        self.first_event(process)
        (self.root / "app.py").write_bytes(b"\xff")
        stdout, stderr = process.communicate(timeout=10)
        self.assertEqual(process.returncode, 2, stderr)
        self.assertEqual(stdout, "")
        self.assertNotIn("Traceback", stderr)

    def test_watch_stops_if_rules_change(self):
        baseline = self.write_json("baseline.json", self.scan())
        process = self.start_watch(baseline, "--interval", "0.3", "--iterations", "2")
        self.first_event(process)
        rules = json.loads(self.rules.read_text())
        rules["rules"][0]["pattern"] = "different-pattern"
        self.rules.write_text(json.dumps(rules))
        stdout, stderr = process.communicate(timeout=10)
        self.assertEqual(process.returncode, 2, stderr)
        self.assertEqual(stdout, "")

    def test_watch_rejects_invalid_timing_and_counts(self):
        baseline = self.write_json("baseline.json", self.scan())
        for option, value in (
            ("--interval", "0"),
            ("--interval", "nan"),
            ("--interval", "inf"),
            ("--iterations", "-1"),
            ("--scan-timeout", "-1"),
            ("--scan-timeout", "nan"),
        ):
            with self.subTest(option=option, value=value):
                result = subprocess.run(
                    self.watch_command(baseline, option, value),
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10,
                )
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, "")

    def test_watch_interrupt_exits_without_traceback(self):
        baseline = self.write_json("baseline.json", self.scan())
        process = self.start_watch(baseline, "--interval", "30")
        self.first_event(process)
        process.send_signal(signal.SIGINT)
        stdout, stderr = process.communicate(timeout=5)
        self.assertEqual(process.returncode, 130, stderr)
        self.assertEqual(stdout, "")
        self.assertNotIn("Traceback", stderr)

    def test_watch_uses_original_baseline_even_if_file_changes(self):
        (self.root / "app.py").write_text("eval('existing')\n")
        baseline = self.write_json("baseline.json", self.scan())
        process = self.start_watch(baseline, "--interval", "0.3", "--iterations", "2")
        self.first_event(process)
        baseline.write_text("{broken-external-change")
        (self.root / "app.py").write_text("print('fixed')\n")
        stdout, stderr = process.communicate(timeout=10)
        self.assertEqual(process.returncode, 0, stderr)
        (event,) = [json.loads(line) for line in stdout.splitlines()]
        self.assertEqual(len(event["resolved"]), 1)
        self.assertEqual(event["new"], [])
        self.assertEqual(baseline.read_text(), "{broken-external-change")

    def test_scan_rejects_invalid_timeouts(self):
        for value in ("0", "nan", "inf", "-1"):
            with self.subTest(value=value):
                self.cli(
                    "scan",
                    "--root",
                    self.root,
                    "--rules",
                    self.rules,
                    "--timeout",
                    value,
                    code=2,
                )

    def test_interrupt_during_regex_scan_cleans_up_worker(self):
        rules = json.loads(self.rules.read_text())
        rules["rules"][0]["pattern"] = "(a+)+$"
        self.rules.write_text(json.dumps(rules))
        (self.root / "app.py").write_text("a" * 200 + "!SECRET_CANARY_8379")
        process = subprocess.Popen(
            [
                sys.executable,
                str(SCRIPT),
                "scan",
                "--root",
                str(self.root),
                "--rules",
                str(self.rules),
                "--timeout",
                "30",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        def cleanup():
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)

        self.addCleanup(cleanup)
        time.sleep(0.5)
        process.send_signal(signal.SIGINT)
        stdout, stderr = process.communicate(timeout=5)
        self.assertEqual(process.returncode, 130, stderr)
        self.assertEqual(stdout, "")
        self.assertNotIn("Traceback", stderr)
        self.assertNotIn("SECRET_CANARY_8379", stderr)

    def fake_scanner(self, tool="Semgrep", mode="ok"):
        executable = self.home / "fake scanner"
        log = self.home / "scanner-args.json"
        code = (
            f"#!{sys.executable}\n"
            f"MODE = {mode!r}\nTOOL = {tool!r}\nLOG = {str(log)!r}\n"
            + textwrap.dedent("""\
                import json, os, pathlib, subprocess, sys, time
                args = sys.argv[1:]
                pathlib.Path(LOG).write_text(json.dumps({
                    "args": args, "cwd": os.getcwd(),
                    "metrics": os.environ.get("SEMGREP_SEND_METRICS"),
                    "version_check": os.environ.get("SEMGREP_ENABLE_VERSION_CHECK"),
                }))
                print("SECRET_CANARY_8379", flush=True)
                print("SECRET_CANARY_8379", file=sys.stderr, flush=True)
                if MODE == "fail": sys.exit(7)
                if MODE == "missing": sys.exit(0)
                if MODE == "hang":
                    time.sleep(30)
                if MODE in ("descendant", "descendant-exit"):
                    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
                    pathlib.Path(LOG + ".pid").write_text(str(child.pid))
                    if MODE == "descendant": time.sleep(30)
                output = (args[args.index("--output") + 1] if "--output" in args else
                          next(a.split("=", 1)[1] for a in args if a.startswith("--output=")))
                if MODE == "malformed":
                    pathlib.Path(output).write_text("{not-json")
                    sys.exit(0)
                if MODE == "oversized":
                    with pathlib.Path(output).open("wb") as report:
                        report.seek(64 * 1024 * 1024)
                        report.write(b"x")
                    sys.exit(0)
                if MODE == "changed":
                    config = args[args.index("--config") + 1] if "--config" in args else args[-1]
                    pathlib.Path(config).write_text("changed-during-run")
                data = {"version": "2.1.0", "runs": [{
                    "tool": {"driver": {"name": TOOL, "version": "1.0", "rules": [{"id": "r1"}]}},
                    "invocations": [{"executionSuccessful": True}],
                    "results": [{"ruleId": "r1", "message": {"text": "SECRET_CANARY_8379"},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"},
                            "region": {"startLine": 1}}}]}],
                }]}
                if MODE == "failed-report":
                    data["runs"][0]["invocations"][0]["executionSuccessful"] = False
                pathlib.Path(output).write_text(json.dumps(data))
                """)
        )
        executable.write_text(code)
        executable.chmod(0o700)
        return executable

    def run_scanner(self, tool="Semgrep", mode="ok", *extra, code=0):
        executable = self.fake_scanner(tool, mode)
        if tool == "Semgrep":
            args = ["run-semgrep", "--root", self.root, "--config", self.rules]
        else:
            database = self.home / "existing-database"
            database.mkdir(exist_ok=True)
            args = [
                "run-codeql",
                "--root",
                self.root,
                "--database",
                database,
                "--suite",
                self.rules,
            ]
        return self.cli(*args, "--executable", executable, *extra, code=code)

    def test_semgrep_runner_normalizes_results_and_uses_local_safe_flags(self):
        result = self.run_scanner()
        (finding,) = result["findings"]
        self.assertEqual(
            (finding["source"], finding["path"], finding["cvss_status"]),
            ("Semgrep", "app.py", "Unscored"),
        )
        self.assertNotIn("SECRET_CANARY_8379", json.dumps(result))
        log = json.loads((self.home / "scanner-args.json").read_text())
        self.assertEqual(Path(log["cwd"]).resolve(), self.root.resolve())
        self.assertIn("--metrics=off", log["args"])
        self.assertIn("--disable-version-check", log["args"])
        self.assertNotIn("--autofix", log["args"])
        self.assertEqual(log["metrics"], "off")

    def test_codeql_runner_uses_existing_database_and_suite_without_download(self):
        result = self.run_scanner("CodeQL")
        self.assertEqual(result["findings"][0]["source"], "CodeQL")
        args = json.loads((self.home / "scanner-args.json").read_text())["args"]
        self.assertEqual(args[:2], ["database", "analyze"])
        self.assertIn("--format=sarifv2.1.0", args)
        self.assertNotIn("--download", args)
        self.assertIn(str(self.rules.resolve()), args)

    def test_scanner_failures_never_emit_snapshot_or_raw_logs(self):
        for mode in (
            "fail",
            "missing",
            "malformed",
            "changed",
            "oversized",
            "failed-report",
        ):
            with self.subTest(mode=mode):
                result = self.run_scanner(mode=mode, code=2)
                self.assertNotIn("SECRET_CANARY_8379", result.stderr)

    def test_scanner_timeout_never_returns_partial_results(self):
        started = time.monotonic()
        result = self.run_scanner("Semgrep", "hang", "--timeout", "0.3", code=2)
        self.assertLess(time.monotonic() - started, 6)
        self.assertNotIn("SECRET_CANARY_8379", result.stderr)

    def test_scanner_configuration_changes_invalidate_snapshot_comparison(self):
        before = self.run_scanner()
        self.rules.write_text(self.rules.read_text() + "\n")
        after = self.run_scanner()
        self.compare(before, after, code=2)

    def test_scanner_missing_executable_or_remote_config_is_not_clean(self):
        self.cli(
            "run-semgrep",
            "--root",
            self.root,
            "--config",
            self.rules,
            "--executable",
            self.home / "missing-scanner",
            code=2,
        )
        executable = self.fake_scanner()
        self.cli(
            "run-semgrep",
            "--root",
            self.root,
            "--config",
            "p/default",
            "--executable",
            executable,
            code=2,
        )
        self.assertFalse((self.home / "scanner-args.json").exists())

    def test_scanner_descendants_stop_on_timeout_and_after_success(self):
        for mode, code in (("descendant", 2), ("descendant-exit", 0)):
            with self.subTest(mode=mode):
                self.run_scanner("Semgrep", mode, "--timeout", "0.5", code=code)
                pid = int((self.home / "scanner-args.json.pid").read_text())

                def cleanup(pid=pid):
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

                self.addCleanup(cleanup)
                state = subprocess.run(
                    ["ps", "-p", str(pid), "-o", "stat="],
                    capture_output=True,
                    text=True,
                    check=False,
                ).stdout.strip()
                self.assertTrue(not state or state.startswith("Z"), state)

    def test_codeql_local_suite_with_pack_syntax_characters_is_unambiguous(self):
        original = self.rules
        self.rules = self.home / "rules@v1.qls"
        self.rules.write_bytes(original.read_bytes())
        self.run_scanner("CodeQL")
        args = json.loads((self.home / "scanner-args.json").read_text())["args"]
        self.assertIn("path:" + str(self.rules.resolve()), args)

    def test_scanner_interrupt_does_not_emit_logs_or_a_snapshot(self):
        executable = self.fake_scanner(mode="hang")
        process = subprocess.Popen(
            [
                sys.executable,
                str(SCRIPT),
                "run-semgrep",
                "--root",
                str(self.root),
                "--config",
                str(self.rules),
                "--executable",
                str(executable),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        def cleanup():
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)

        self.addCleanup(cleanup)
        deadline = time.monotonic() + 5
        while (
            not (self.home / "scanner-args.json").is_file()
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)
        self.assertTrue((self.home / "scanner-args.json").is_file())
        process.send_signal(signal.SIGINT)
        stdout, stderr = process.communicate(timeout=5)
        self.assertEqual(process.returncode, 130, stderr)
        self.assertEqual(stdout, "")
        self.assertNotIn("Traceback", stderr)
        self.assertNotIn("SECRET_CANARY_8379", stderr)


if __name__ == "__main__":
    unittest.main()
