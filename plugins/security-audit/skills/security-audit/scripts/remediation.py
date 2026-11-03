"""Apply a reviewed patch in an isolated Git worktree and optionally publish it."""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


class RemediationError(ValueError):
    """A fixed message which contains no command output or patch content."""


def require(condition, message):
    if not condition:
        raise RemediationError(message)


def add_arguments(commands, positive_seconds):
    command = commands.add_parser("remediate")
    for name in ("root", "patch", "branch", "test-command"):
        command.add_argument("--" + name, required=True)
    command.add_argument("--base", default="HEAD")
    command.add_argument("--timeout", type=positive_seconds, default=300.0)
    command.add_argument("--publish", action="store_true")
    for name in ("repo", "title", "body-file"):
        command.add_argument("--" + name)
    command.add_argument("--pr-base", default="main")
    command.add_argument("--gh-executable", default="gh")


def remediate(args, stop_process):
    require(os.name == "posix", "Remediation requires POSIX")
    require(
        not args.publish or all((args.repo, args.title, args.body_file)),
        "Publication metadata is required",
    )
    try:
        tests = json.loads(args.test_command)
    except ValueError:
        raise RemediationError("Invalid test command JSON") from None
    require(
        isinstance(tests, list)
        and tests
        and all(isinstance(x, str) and x.strip() and "\0" not in x for x in tests),
        "Test command must be a nonempty argument array",
    )
    root = Path(args.root).resolve(strict=True)
    require(root.is_dir(), "Root must be a directory")
    patch = Path(args.patch).read_bytes()
    require(
        patch and b"\0" not in patch and b"GIT binary patch" not in patch.split(b"\n"),
        "Patch must be nonempty UTF-8 text",
    )
    try:
        patch.decode("utf-8")
    except UnicodeError:
        raise RemediationError("Patch must be nonempty UTF-8 text") from None
    require(
        args.branch and not args.branch.startswith("-") and "\0" not in args.branch,
        "Invalid remediation branch",
    )
    require(
        args.base and not args.base.startswith("-") and "\0" not in args.base,
        "Invalid base revision",
    )
    environment = os.environ.copy()
    for key in (
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_COMMON_DIR",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    ):
        environment.pop(key, None)
    environment.update(
        GIT_TERMINAL_PROMPT="0",
        GH_PROMPT_DISABLED="1",
        GH_HOST="github.com",
        GIT_NO_REPLACE_OBJECTS="1",
    )
    deadline = time.monotonic() + args.timeout

    def run(argv, cwd=root, capture=False, allowed=(0,), cleanup=False):
        remaining = deadline - time.monotonic()
        require(cleanup or remaining > 0, "Remediation timeout exceeded")
        with tempfile.TemporaryFile() as output:
            process = subprocess.Popen(
                argv,
                cwd=cwd,
                env=environment,
                stdout=output if capture else subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            try:
                command_deadline = time.monotonic() + 10 if cleanup else deadline
                while process.poll() is None:
                    remaining = command_deadline - time.monotonic()
                    require(remaining > 0, "Remediation timeout exceeded")
                    try:
                        process.wait(timeout=min(remaining, 60))
                    except subprocess.TimeoutExpired:
                        pass
                require(process.returncode in allowed, "Remediation command failed")
            finally:
                stop_process(process)
            output.seek(0)
            return process.returncode, output.read() if capture else b""

    def git(*values, cwd=root, **kwargs):
        return run(["git", *values], cwd=cwd, **kwargs)

    def metadata(*values, cwd=root):
        return git(*values, cwd=cwd, capture=True)[1].decode("utf-8").strip()

    require(
        Path(metadata("rev-parse", "--show-toplevel")).resolve() == root,
        "Root must match Git repository root",
    )
    git("check-ref-format", "refs/heads/" + args.branch)
    git("check-ref-format", "--branch", args.branch)
    base = metadata(
        "rev-parse", "--verify", "--end-of-options", args.base + "^{commit}"
    )
    require(re.fullmatch(r"[0-9a-f]{40,64}", base), "Invalid base commit")
    body = Path(args.body_file).read_bytes() if args.publish else None
    directory = Path(tempfile.mkdtemp(prefix="audit-remediate-"))
    worktree = directory / "worktree"
    patch_file = directory / "reviewed.patch"
    patch_file.write_bytes(patch)
    body_file = directory / "pr-body.md"
    if args.publish:
        body_file.write_bytes(body)
    owned_branch = False
    owned_worktree = False
    committed = False
    publish_started = False
    result = None
    try:
        git("update-ref", "refs/heads/" + args.branch, base, "")
        owned_branch = True
        git("worktree", "add", "--", str(worktree), args.branch)
        owned_worktree = True
        git("apply", "--check", "--index", "--", str(patch_file), cwd=worktree)
        git("apply", "--index", "--", str(patch_file), cwd=worktree)
        raw = git(
            "diff",
            "--cached",
            "--raw",
            "--no-abbrev",
            "--no-renames",
            "-z",
            base,
            "--",
            cwd=worktree,
            capture=True,
        )[1].split(b"\0")
        require(
            len(raw) > 1 and (len(raw) - 1) % 2 == 0, "Patch has no supported changes"
        )
        for record in raw[:-1:2]:
            values = record.split()
            require(len(values) == 5, "Invalid staged patch")
            old, new, _old_id, _new_id, status = values
            old = old.lstrip(b":")
            require(
                new in {b"100644", b"100755"}
                and (
                    (status == b"A" and old == b"000000")
                    or (status == b"M" and old == new)
                ),
                "Patch supports regular file additions and modifications only",
            )
        numstat = git(
            "diff",
            "--cached",
            "--numstat",
            "-z",
            base,
            "--",
            cwd=worktree,
            capture=True,
        )[1]
        require(
            all(not row.startswith(b"-\t") for row in numstat.split(b"\0")),
            "Binary patches are unsupported",
        )
        tree = metadata("write-tree", cwd=worktree)

        def unchanged():
            require(
                metadata("write-tree", cwd=worktree) == tree,
                "Validation changed the staged patch",
            )
            git("diff", "--quiet", "--", cwd=worktree)
            require(
                not git(
                    "ls-files",
                    "--others",
                    "--exclude-standard",
                    "-z",
                    cwd=worktree,
                    capture=True,
                )[1],
                "Validation left untracked files",
            )

        require(
            metadata("symbolic-ref", "HEAD", cwd=worktree)
            == "refs/heads/" + args.branch,
            "Unexpected remediation branch",
        )
        run(tests, cwd=worktree)
        unchanged()
        require(
            metadata("rev-parse", "HEAD", cwd=worktree) == base,
            "Validation changed the base commit",
        )
        require(
            metadata("symbolic-ref", "HEAD", cwd=worktree)
            == "refs/heads/" + args.branch,
            "Validation changed the remediation branch",
        )
        git(
            "commit",
            "-m",
            args.title or "fix: apply reviewed security remediation",
            cwd=worktree,
        )
        committed = True
        commit = metadata("rev-parse", "HEAD", cwd=worktree)
        require(
            metadata("rev-parse", "refs/heads/" + args.branch) == commit,
            "Commit changed the remediation branch",
        )
        raw_commit = git("cat-file", "commit", commit, cwd=worktree, capture=True)[1]
        headers = raw_commit.split(b"\n\n", 1)[0].split(b"\n")
        trees = [line[5:] for line in headers if line.startswith(b"tree ")]
        parents = [line[7:] for line in headers if line.startswith(b"parent ")]
        require(
            trees == [tree.encode("ascii")], "Commit differs from the reviewed patch"
        )
        require(
            parents == [base.encode("ascii")], "Commit changed the remediation ancestry"
        )
        unchanged()
        result = {
            "schema_version": 1,
            "branch": args.branch,
            "base_commit": base,
            "commit": commit,
            "tests_passed": True,
            "published": False,
            "pr_url": None,
        }
        if args.publish:
            require(
                re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repo),
                "Invalid GitHub repository",
            )
            git("check-ref-format", "refs/heads/" + args.pr_base)
            urls = metadata("config", "--get-all", "remote.origin.url").splitlines()
            require(len(urls) == 1, "A single GitHub origin URL is required")
            origin = urls[0]
            match = re.fullmatch(
                r"(?:https://github\.com/|git@github\.com:|ssh://git@github\.com/)([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?/?",
                origin,
            )
            require(
                match and match[1].lower() == args.repo.lower(),
                "GitHub origin does not match requested repository",
            )
            code, pushurl = git(
                "config",
                "--get-all",
                "remote.origin.pushurl",
                capture=True,
                allowed=(0, 1),
            )
            require(
                code == 1 and not pushurl, "Separate origin push URLs are unsupported"
            )
            gh = shutil.which(args.gh_executable)
            require(gh is not None, "GitHub CLI executable unavailable")
            refs = metadata(
                "ls-remote",
                "--refs",
                origin,
                "refs/heads/" + args.pr_base,
                "refs/heads/" + args.branch,
            )
            remote = dict(line.split("\t")[::-1] for line in refs.splitlines())
            require(
                "refs/heads/" + args.branch not in remote,
                "Remote branch already exists",
            )
            target = remote.get("refs/heads/" + args.pr_base)
            require(
                target and re.fullmatch(r"[0-9a-f]{40,64}", target),
                "Remote PR base is unavailable",
            )
            code, _ = git(
                "merge-base", "--is-ancestor", target, base, allowed=(0, 1, 128)
            )
            require(
                code == 0,
                "Remote PR base ancestry is unavailable; fetch and review the base",
            )
            publish_started = True
            git(
                "push",
                "--no-follow-tags",
                "--recurse-submodules=no",
                "--force-with-lease=refs/heads/" + args.branch + ":",
                "--",
                origin,
                commit + ":refs/heads/" + args.branch,
            )
            url = (
                run(
                    [
                        str(Path(gh).resolve()),
                        "pr",
                        "create",
                        "--draft",
                        "--repo",
                        args.repo,
                        "--base",
                        args.pr_base,
                        "--head",
                        args.branch,
                        "--title",
                        args.title,
                        "--body-file",
                        str(body_file),
                    ],
                    cwd=worktree,
                    capture=True,
                )[1]
                .decode()
                .strip()
            )
            require(
                re.fullmatch(
                    r"https://github\.com/" + re.escape(args.repo) + r"/pull/[0-9]+",
                    url,
                ),
                "GitHub CLI returned an invalid PR URL",
            )
            result.update(published=True, pr_url=url)
    except KeyboardInterrupt:
        if publish_started:
            print(
                "Publication interrupted; remote branch or PR may exist.",
                file=sys.stderr,
            )
        raise
    except Exception:
        if publish_started:
            raise RemediationError(
                "Publication failed; remote branch or PR may exist"
            ) from None
        raise
    finally:
        try:
            if owned_worktree or worktree.exists():
                git("worktree", "remove", "--force", "--", str(worktree), cleanup=True)
            if owned_branch and not committed and not publish_started:
                git(
                    "update-ref",
                    "-d",
                    "refs/heads/" + args.branch,
                    base,
                    allowed=(0, 1),
                    cleanup=True,
                )
        except Exception:  # noqa: BLE001 - cleanup failures must not hide ownership state
            raise RemediationError(
                "Remediation cleanup failed; isolated worktree retained"
            ) from None
        else:
            try:
                shutil.rmtree(directory)
            except OSError:
                raise RemediationError(
                    "Remediation cleanup failed; private directory retained"
                ) from None
    return result
