"""Local, read-only audit workflow helpers (Python 3.10+)."""

import argparse
import fnmatch
import hashlib
import json
import math
import multiprocessing
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import unquote, urljoin, urlparse

MAX_FILE_SIZE = 1024 * 1024
LEVELS = {"none", "note", "warning", "error"}


class WorkflowError(ValueError):
    """A fixed, safe-to-display validation message."""


def require(condition, message):
    if not condition:
        raise WorkflowError(message)


def read_json(path):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "Duplicate JSON key")
            result[key] = value
        return result

    return json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=pairs)


def digest(value):
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
    ).hexdigest()


def fingerprint(source, rule, path, line):
    return digest([source, rule, path, line])


def root_dir(value):
    path = Path(value).resolve(strict=True)
    require(path.is_dir(), "Root must be a directory")
    return path


def nonempty(value):
    return isinstance(value, str) and bool(value.strip())


def relative_path(value):
    require(
        nonempty(value) and "\\" not in value and "\x00" not in value,
        "Invalid finding path",
    )
    path = Path(value)
    require(
        not path.is_absolute()
        and all(p not in {"", ".", ".."} for p in value.split("/")),
        "Finding path must be root-relative",
    )
    return value


def finding(source, rule, path, line, message, level):
    require(type(line) is int and line > 0, "Invalid finding line")
    relative_path(path)
    return {
        "fingerprint": fingerprint(source, rule, path, line),
        "source": source,
        "rule_id": rule,
        "path": path,
        "line": line,
        "message": message,
        "scanner_level": level,
        "cvss_status": "Unscored",
    }


def scan_work(args):
    root = root_dir(args.root)
    config = read_json(args.rules)
    require(
        isinstance(config, dict)
        and set(config) == {"rules"}
        and isinstance(config["rules"], list),
        "Invalid rules configuration",
    )
    rules, seen = [], set()
    for rule in config["rules"]:
        require(
            isinstance(rule, dict)
            and set(rule) == {"id", "pattern", "include", "message", "level"},
            "Invalid rule fields",
        )
        require(
            nonempty(rule["id"]) and rule["id"] not in seen,
            "Invalid or duplicate rule ID",
        )
        require(
            nonempty(rule["pattern"])
            and nonempty(rule["message"])
            and rule["level"] in LEVELS,
            "Invalid rule values",
        )
        require(
            isinstance(rule["include"], list)
            and rule["include"]
            and all(
                nonempty(p) and not p.startswith("/") and ".." not in p.split("/")
                for p in rule["include"]
            ),
            "Invalid include patterns",
        )
        try:
            expression = re.compile(rule["pattern"])
        except re.error:
            raise WorkflowError("Invalid rule regular expression") from None
        seen.add(rule["id"])
        rules.append((rule, expression))
    findings = []

    def walk_error(_error):
        raise WorkflowError("Unable to inspect scan directory")

    for directory, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
        dirs[:] = sorted(
            d for d in dirs if d != ".git" and not (Path(directory) / d).is_symlink()
        )
        for name in sorted(files):
            path = Path(directory) / name
            if name == ".git" or path.is_symlink() or not path.is_file():
                continue
            relative = path.relative_to(root).as_posix()
            selected = [
                (r, rx)
                for r, rx in rules
                if any(
                    fnmatch.fnmatchcase(relative, p)
                    or (p.startswith("**/") and fnmatch.fnmatchcase(relative, p[3:]))
                    for p in r["include"]
                )
            ]
            if not selected:
                continue
            require(path.stat().st_size <= MAX_FILE_SIZE, "Included file exceeds 1 MiB")
            with path.open("rb") as stream:
                content = stream.read(MAX_FILE_SIZE + 1)
            require(len(content) <= MAX_FILE_SIZE, "Included file exceeds 1 MiB")
            try:
                text = content.decode("utf-8")
            except UnicodeDecodeError:
                raise WorkflowError("Included file is not UTF-8") from None
            for rule, expression in selected:
                lines = sorted(
                    {
                        text.count("\n", 0, match.start()) + 1
                        for match in expression.finditer(text)
                    }
                )
                for line in lines:
                    findings.append(
                        finding(
                            "custom",
                            rule["id"],
                            relative,
                            line,
                            rule["message"],
                            rule["level"],
                        )
                    )
    return {
        "schema_version": 1,
        "coverage": {
            "kind": "custom",
            "rules_digest": digest(config),
            "root": str(root),
        },
        "findings": sorted(findings, key=lambda f: f["fingerprint"]),
    }


def scan_worker(root, rules, output):
    """Keep regex evaluation and accumulated findings outside the CLI process."""
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        result = {"result": scan_work(argparse.Namespace(root=root, rules=rules))}
    except WorkflowError as error:
        result = {"error": str(error)}
    except Exception:  # noqa: BLE001 - suppress worker tracebacks and source leakage
        result = {"error": "Invalid scan input or worker error"}
    try:
        Path(output).write_text(json.dumps(result, ensure_ascii=True), encoding="utf-8")
    except BaseException:  # noqa: BLE001 - never emit a worker traceback
        os._exit(2)


def scan(args):
    timeout = getattr(args, "timeout", 30.0)
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="audit-scan-") as directory:
        output = str(Path(directory) / "result.json")
        process = multiprocessing.get_context("spawn").Process(
            target=scan_worker, args=(args.root, args.rules, output)
        )
        try:
            process.start()
            while process.is_alive():
                remaining = timeout - (time.monotonic() - started)
                require(remaining > 0, "Scan timeout exceeded")
                process.join(min(remaining, 60.0))
            require(time.monotonic() - started <= timeout, "Scan timeout exceeded")
            require(
                process.exitcode == 0 and Path(output).is_file(), "Scan worker failed"
            )
            result = read_json(output)
            require(isinstance(result, dict), "Invalid scan worker result")
            if "error" in result:
                raise WorkflowError(result["error"])
            require(set(result) == {"result"}, "Invalid scan worker result")
            return result["result"]
        finally:
            if process.pid is not None:
                if process.is_alive():
                    process.terminate()
                    process.join(0)
                if process.is_alive():
                    process.kill()
                process.join()
                process.close()


def artifact_uri(location, artifacts, bases, root, visiting=None):
    require(isinstance(location, dict), "Missing SARIF artifact location")
    visiting = set() if visiting is None else visiting
    if "uri" not in location and "index" in location:
        index = location["index"]
        require(
            type(index) is int
            and 0 <= index < len(artifacts)
            and ("artifact", index) not in visiting,
            "Invalid SARIF artifact index",
        )
        return artifact_uri(
            artifacts[index].get("location"),
            artifacts,
            bases,
            root,
            visiting | {("artifact", index)},
        )
    value = location.get("uri")
    require(nonempty(value), "Missing SARIF artifact URI")
    base_id = location.get("uriBaseId")
    if base_id == "%SRCROOT%" and base_id not in bases:
        # Semgrep may omit this conventional base even for absolute paths.
        # The caller still validates URI scheme and containment within root.
        return urljoin(root.as_uri() + "/", value)
    if base_id is not None:
        require(
            base_id in bases and ("base", base_id) not in visiting,
            "Unknown or cyclic SARIF URI base",
        )
        value = urljoin(
            artifact_uri(
                bases[base_id], artifacts, bases, root, visiting | {("base", base_id)}
            ),
            value,
        )
    return value


def sarif(args):
    root = root_dir(args.root)
    data = read_json(args.input)
    require(
        isinstance(data, dict)
        and data.get("version") == "2.1.0"
        and isinstance(data.get("runs"), list)
        and bool(data["runs"]),
        "Expected nonempty SARIF 2.1.0 runs",
    )
    findings, tools, identities = {}, set(), []
    for run in data["runs"]:
        require(isinstance(run, dict), "Invalid SARIF run")
        driver = run.get("tool", {}).get("driver", {})
        tool = driver.get("name")
        require(nonempty(tool), "Missing SARIF tool name")
        tools.add(tool)
        identities.append(
            {
                "driver": driver,
                "extensions": run.get("tool", {}).get("extensions", []),
                "automationDetails": run.get("automationDetails", {}),
                "runAggregates": run.get("runAggregates", []),
            }
        )
        for invocation in run.get("invocations", []):
            require(
                isinstance(invocation, dict)
                and (
                    "executionSuccessful" not in invocation
                    or type(invocation["executionSuccessful"]) is bool
                )
                and invocation.get("executionSuccessful") is not False,
                "SARIF scanner execution failed",
            )
            for key in ("toolExecutionNotifications", "toolConfigurationNotifications"):
                require(
                    all(
                        isinstance(n, dict) and n.get("level") != "error"
                        for n in invocation.get(key, [])
                    ),
                    "SARIF scanner error notification",
                )
        rules = driver.get("rules", [])
        require(
            isinstance(rules, list)
            and all(isinstance(r, dict) and nonempty(r.get("id")) for r in rules),
            "Invalid SARIF rules",
        )
        rule_map = {r["id"]: r for r in rules}
        require(len(rule_map) == len(rules), "Duplicate SARIF rule ID")
        artifacts = run.get("artifacts", [])
        bases = run.get("originalUriBaseIds", {})

        results = run.get("results")
        require(isinstance(results, list), "Invalid SARIF results")
        for result in results:
            require(isinstance(result, dict), "Invalid SARIF result")
            index = result.get("ruleIndex")
            rule = result.get("ruleId")
            if index is not None:
                require(
                    type(index) is int and 0 <= index < len(rules),
                    "Invalid SARIF rule index",
                )
                require(
                    rule is None or rule == rules[index]["id"],
                    "Inconsistent SARIF rule identity",
                )
                rule = rules[index]["id"]
            require(nonempty(rule), "Missing SARIF rule ID")
            level = result.get(
                "level",
                rule_map.get(rule, {})
                .get("defaultConfiguration", {})
                .get("level", "warning"),
            )
            require(level in LEVELS, "Invalid SARIF result level")
            locations = result.get("locations")
            require(
                isinstance(locations, list) and locations,
                "SARIF result requires physical locations",
            )
            for location in locations:
                physical = location.get("physicalLocation", {})
                parsed = urlparse(
                    artifact_uri(
                        physical.get("artifactLocation"), artifacts, bases, root
                    )
                )
                require(
                    parsed.scheme in {"", "file"}
                    and parsed.netloc in {"", "localhost"}
                    and not parsed.query
                    and not parsed.fragment,
                    "Unsupported SARIF artifact URI",
                )
                decoded = unquote(parsed.path)
                require(
                    "\\" not in decoded
                    and "\x00" not in decoded
                    and ".." not in decoded.split("/"),
                    "SARIF artifact path escape",
                )
                target = Path(decoded)
                require(
                    parsed.scheme != "file" or target.is_absolute(),
                    "File URI must be absolute",
                )
                target = (target if target.is_absolute() else root / target).resolve()
                require(
                    target.is_relative_to(root) and target != root,
                    "SARIF artifact outside root",
                )
                relative = target.relative_to(root).as_posix()
                line = physical.get("region", {}).get("startLine")
                entry = finding(
                    tool,
                    rule,
                    relative,
                    line,
                    rule + " scanner finding (review original SARIF)",
                    level,
                )
                previous = findings.get(entry["fingerprint"])
                require(
                    previous is None or previous == entry, "Conflicting SARIF findings"
                )
                findings[entry["fingerprint"]] = entry
    return {
        "schema_version": 1,
        "coverage": {
            "kind": "sarif",
            "tools": sorted(tools),
            "rules_digest": digest(
                sorted(identities, key=lambda v: json.dumps(v, sort_keys=True))
            ),
            "root": str(root),
        },
        "findings": sorted(findings.values(), key=lambda f: f["fingerprint"]),
    }


def validate_snapshot(data):
    require(
        isinstance(data, dict)
        and set(data) == {"schema_version", "coverage", "findings"}
        and type(data["schema_version"]) is int
        and data["schema_version"] == 1,
        "Invalid snapshot schema",
    )
    coverage = data["coverage"]
    require(isinstance(coverage, dict), "Invalid coverage")
    kind = coverage.get("kind")
    require(kind in {"custom", "sarif"}, "Invalid coverage kind")
    require(
        set(coverage)
        == (
            {"kind", "root", "rules_digest"}
            if kind == "custom"
            else {"kind", "root", "tools", "rules_digest"}
        ),
        "Invalid coverage fields",
    )
    require(
        nonempty(coverage["root"])
        and Path(coverage["root"]).is_absolute()
        and str(Path(coverage["root"]).resolve()) == coverage["root"],
        "Invalid coverage root",
    )
    require(
        isinstance(coverage["rules_digest"], str)
        and re.fullmatch(r"[0-9a-f]{64}", coverage["rules_digest"]),
        "Invalid rules digest",
    )
    if kind == "sarif":
        names = coverage["tools"]
        require(
            isinstance(names, list)
            and bool(names)
            and all(nonempty(n) for n in names)
            and names == sorted(set(names)),
            "Invalid tool coverage",
        )
    require(isinstance(data["findings"], list), "Invalid findings")
    entries = {}
    for entry in data["findings"]:
        keys = {
            "fingerprint",
            "source",
            "rule_id",
            "path",
            "line",
            "message",
            "scanner_level",
            "cvss_status",
        }
        require(
            isinstance(entry, dict) and set(entry) == keys, "Invalid finding fields"
        )
        require(
            all(nonempty(entry[k]) for k in ("source", "rule_id", "message"))
            and entry["scanner_level"] in LEVELS
            and entry["cvss_status"] == "Unscored",
            "Invalid finding values",
        )
        require(
            entry["source"] == "custom"
            if kind == "custom"
            else entry["source"] in coverage["tools"],
            "Finding source outside coverage",
        )
        expected = finding(
            entry["source"],
            entry["rule_id"],
            entry["path"],
            entry["line"],
            entry["message"],
            entry["scanner_level"],
        )
        require(
            entry == expected and entry["fingerprint"] not in entries,
            "Invalid or duplicate fingerprint",
        )
        entries[entry["fingerprint"]] = entry
    return coverage, entries


def compare_snapshots(baseline_snapshot, current_snapshot):
    coverage, baseline = baseline_snapshot
    current_coverage, current = current_snapshot
    require(coverage == current_coverage, "Snapshot coverage differs")
    return {
        "schema_version": 1,
        "coverage": coverage,
        "new": [current[k] for k in sorted(current.keys() - baseline.keys())],
        "resolved": [baseline[k] for k in sorted(baseline.keys() - current.keys())],
        "unchanged": [current[k] for k in sorted(current.keys() & baseline.keys())],
    }


def snapshot(path):
    return validate_snapshot(read_json(path))


def monitor(args):
    return compare_snapshots(snapshot(args.baseline), snapshot(args.current))


def watch(args):
    baseline = snapshot(args.baseline)
    expected = {
        "kind": "custom",
        "root": str(root_dir(args.root)),
        "rules_digest": digest(read_json(args.rules)),
    }
    require(baseline[0] == expected, "Snapshot coverage differs")
    iteration = 0
    while args.iterations == 0 or iteration < args.iterations:
        current = scan(
            argparse.Namespace(
                root=args.root, rules=args.rules, timeout=args.scan_timeout
            )
        )
        event = compare_snapshots(baseline, validate_snapshot(current))
        iteration += 1
        event["iteration"] = iteration
        print(json.dumps(event, sort_keys=True, ensure_ascii=True), flush=True)
        if args.fail_on_new and event["new"]:
            return 1
        if args.iterations and iteration >= args.iterations:
            return 0
        deadline = time.monotonic() + args.interval
        while time.monotonic() < deadline:
            time.sleep(min(60.0, max(0.0, deadline - time.monotonic())))
    return 0


def positive_seconds(value):
    try:
        result = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("Expected finite positive seconds") from None
    if not math.isfinite(result) or result <= 0:
        raise argparse.ArgumentTypeError("Expected finite positive seconds")
    return result


def nonnegative_integer(value):
    try:
        result = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("Expected a nonnegative integer") from None
    if result < 0:
        raise argparse.ArgumentTypeError("Expected a nonnegative integer")
    return result


def file_hash(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            value.update(chunk)
    return value.hexdigest()


def stop_scanner(process):
    """Stop the whole new session, including children left after the leader exits."""
    try:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=0.2)
        except subprocess.TimeoutExpired:
            pass
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        finally:
            process.wait()


def run_scanner(args):
    require(os.name == "posix", "Scanner runners require POSIX")
    root = root_dir(args.root)
    executable = shutil.which(args.executable)
    require(executable is not None, "Scanner executable unavailable")
    executable = str(Path(executable).resolve(strict=True))
    kind = "semgrep" if args.command == "run-semgrep" else "codeql"
    config = Path(args.config if kind == "semgrep" else args.suite).resolve(strict=True)
    require(config.is_file(), "Scanner configuration must be a local file")
    before = file_hash(config)
    database = root_dir(args.database) if kind == "codeql" else None
    environment = os.environ.copy()
    with tempfile.TemporaryDirectory(prefix="audit-scanner-") as directory:
        report = Path(directory) / "report.sarif"
        if kind == "semgrep":
            command = [
                executable,
                "scan",
                "--config",
                str(config),
                "--metrics=off",
                "--disable-version-check",
                "--sarif",
                "--output",
                str(report),
                str(root),
            ]
            environment.update(
                SEMGREP_SEND_METRICS="off", SEMGREP_ENABLE_VERSION_CHECK="0"
            )
        else:
            suite = (
                "path:" + str(config)
                if any(c in str(config) for c in "@:")
                else str(config)
            )
            command = [
                executable,
                "database",
                "analyze",
                "--format=sarifv2.1.0",
                "--output=" + str(report),
                "--",
                str(database),
                suite,
            ]
        started = time.monotonic()
        process = subprocess.Popen(
            command,
            cwd=root,
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        try:
            remaining = args.timeout - (time.monotonic() - started)
            require(remaining > 0, "Scanner timeout exceeded")
            # Small waits also support finite values beyond the OS timeout range.
            while process.poll() is None:
                remaining = args.timeout - (time.monotonic() - started)
                require(remaining > 0, "Scanner timeout exceeded")
                try:
                    process.wait(timeout=min(remaining, 60.0))
                except subprocess.TimeoutExpired:
                    pass
            require(process.returncode == 0, "Scanner execution failed")
        finally:
            stop_scanner(process)
        require(
            config.is_file() and file_hash(config) == before,
            "Scanner configuration changed during execution",
        )
        require(
            report.is_file() and report.stat().st_size <= 64 * 1024 * 1024,
            "Scanner report missing or exceeds size limit",
        )
        result = sarif(argparse.Namespace(root=str(root), input=str(report)))
        result["coverage"]["rules_digest"] = digest(
            {
                "imported_digest": result["coverage"]["rules_digest"],
                "runner": kind,
                "config_hash": before,
                "database": str(database) if database else None,
                "executable": executable,
            }
        )
        return result


def check_patch(args):
    root = root_dir(args.root)
    patch = Path(args.patch).resolve(strict=True)
    require(patch.is_file(), "Patch must be a regular file")

    def git(*arguments):
        return subprocess.run(
            ["git", "-C", str(root), *arguments],
            capture_output=True,
            timeout=30,
            check=False,
        )

    result = git("rev-parse", "--show-toplevel")
    require(
        result.returncode == 0
        and Path(os.fsdecode(result.stdout).strip()).resolve() == root,
        "Root must match Git repository root",
    )
    result = git("apply", "--check", "--", str(patch))
    require(result.returncode == 0, "Patch applicability check failed")
    return {"schema_version": 1, "applicable": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("scan", "import-sarif", "check-patch"):
        command = commands.add_parser(name)
        command.add_argument("--root", required=True)
        command.add_argument(
            {"scan": "--rules", "import-sarif": "--input", "check-patch": "--patch"}[
                name
            ],
            required=True,
        )
        if name == "scan":
            command.add_argument("--timeout", type=positive_seconds, default=30.0)
    for name in ("run-semgrep", "run-codeql"):
        command = commands.add_parser(name)
        command.add_argument("--root", required=True)
        command.add_argument(
            "--executable", default="semgrep" if name == "run-semgrep" else "codeql"
        )
        command.add_argument("--timeout", type=positive_seconds, default=300.0)
        if name == "run-semgrep":
            command.add_argument("--config", required=True)
        else:
            command.add_argument("--database", required=True)
            command.add_argument("--suite", required=True)
    command = commands.add_parser("watch")
    command.add_argument("--root", required=True)
    command.add_argument("--rules", required=True)
    command.add_argument("--baseline", required=True)
    command.add_argument("--interval", type=positive_seconds, default=30.0)
    command.add_argument("--iterations", type=nonnegative_integer, default=0)
    command.add_argument("--scan-timeout", type=positive_seconds, default=30.0)
    command.add_argument("--fail-on-new", action="store_true")
    command = commands.add_parser("monitor")
    command.add_argument("--baseline", required=True)
    command.add_argument("--current", required=True)
    command.add_argument("--fail-on-new", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "watch":
            return watch(args)
        result = {
            "scan": scan,
            "run-semgrep": run_scanner,
            "run-codeql": run_scanner,
            "import-sarif": sarif,
            "monitor": monitor,
            "check-patch": check_patch,
        }[args.command](args)
    except KeyboardInterrupt:
        return 130
    except WorkflowError as error:
        print("Audit workflow failed: " + str(error) + ".", file=sys.stderr)
        return 2
    except (
        ValueError,
        OSError,
        TypeError,
        KeyError,
        AttributeError,
        RecursionError,
        subprocess.SubprocessError,
    ):
        # Do not echo source, scanner messages, regexes, or patch content on errors.
        print("Audit workflow failed: invalid input or tool error.", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, ensure_ascii=True))
    return 1 if args.command == "monitor" and args.fail_on_new and result["new"] else 0


if __name__ == "__main__":
    sys.exit(main())
