"""Run remediation in temporary repositories; publication stays on a local remote."""

import json
import os
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/audit_workflow.py"


class RemediationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name)
        self.root = self.home / "project"
        self.root.mkdir()
        self.git("init", "-q", "--initial-branch=main")
        self.git("config", "user.name", "Remediation Test")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        (self.root / "app.py").write_text("eval('input')\n")
        (self.root / ".gitignore").write_text("__pycache__/\n")
        self.git("add", "app.py", ".gitignore")
        self.git("commit", "-qm", "fixture")
        self.base = self.git("rev-parse", "HEAD").strip()
        (self.root / "app.py").write_text("print('input')\n")
        self.patch = self.home / "reviewed.patch"
        self.patch.write_text(self.git("diff"))
        self.git("restore", "app.py")
        self.branch = "security/reviewed-fix"
        self.test_command = [
            sys.executable,
            "-c",
            "from pathlib import Path; assert Path('app.py').read_text() == \"print('input')\\n\"; print('SECRET_CANARY_8379')",
        ]

    def git(self, *args, code=0):
        result = subprocess.run(
            ["git", "-C", str(self.root), *args],
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
        self.assertEqual(result.returncode, code, result.stderr)
        return result.stdout

    def command(self, *extra, test=None):
        return [
            sys.executable,
            str(SCRIPT),
            "remediate",
            "--root",
            str(self.root),
            "--patch",
            str(self.patch),
            "--branch",
            self.branch,
            "--test-command",
            json.dumps(self.test_command if test is None else test),
            *extra,
        ]

    def run_fix(self, *extra, test=None, code=0):
        result = subprocess.run(
            self.command(*extra, test=test),
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
        )
        self.assertEqual(result.returncode, code, result.stderr)
        self.assertNotIn("SECRET_CANARY_8379", result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        if code:
            self.assertEqual(result.stdout, "")
            return result
        return json.loads(result.stdout)

    def assert_branch_absent(self):
        self.git("show-ref", "--verify", "--quiet", "refs/heads/" + self.branch, code=1)

    def test_local_remediation_commits_only_in_isolated_branch(self):
        (self.root / "app.py").write_text("eval('input')\n# user uncommitted edit\n")
        (self.root / "notes.txt").write_text("user staged note")
        self.git("add", "notes.txt")
        before = self.git("status", "--porcelain")
        worktrees = self.git("worktree", "list", "--porcelain")
        result = self.run_fix()
        self.assertEqual(result["schema_version"], 1)
        self.assertEqual(result["branch"], self.branch)
        self.assertEqual(result["base_commit"], self.base)
        self.assertFalse(result["published"])
        self.assertIsNone(result["pr_url"])
        self.assertTrue(result["tests_passed"])
        self.assertEqual(self.git("show", self.branch + ":app.py"), "print('input')\n")
        self.assertEqual(self.git("rev-parse", "HEAD").strip(), self.base)
        self.assertEqual(self.git("status", "--porcelain"), before)
        self.assertEqual(self.git("worktree", "list", "--porcelain"), worktrees)
        self.assertEqual(
            (self.root / "app.py").read_text(),
            "eval('input')\n# user uncommitted edit\n",
        )

    def test_failed_tests_create_no_commit_or_publication(self):
        before = self.git("status", "--porcelain")
        self.run_fix(test=[sys.executable, "-c", "raise SystemExit(1)"], code=2)
        self.assert_branch_absent()
        self.assertEqual(self.git("status", "--porcelain"), before)
        self.assertEqual(len(self.git("worktree", "list").splitlines()), 1)

    def test_tests_cannot_silently_change_the_committed_patch(self):
        test = [
            sys.executable,
            "-c",
            "from pathlib import Path; Path('app.py').write_text('unexpected')",
        ]
        self.run_fix(test=test, code=2)
        self.assert_branch_absent()

    def test_tests_cannot_silently_stage_additional_changes(self):
        test = [
            sys.executable,
            "-c",
            "from pathlib import Path; import subprocess; Path('extra.txt').write_text('unexpected'); subprocess.run(['git','add','extra.txt'],check=True)",
        ]
        self.run_fix(test=test, code=2)
        self.assert_branch_absent()

    def test_ignored_test_artifacts_are_not_committed(self):
        test = [
            sys.executable,
            "-c",
            "from pathlib import Path; p=Path('__pycache__'); p.mkdir(); (p/'generated').write_text('temporary')",
        ]
        result = self.run_fix(test=test)
        files = self.git("ls-tree", "-r", "--name-only", result["commit"])
        self.assertNotIn("generated", files)

    def test_existing_branch_is_preserved_and_rejected(self):
        self.git("branch", self.branch)
        self.run_fix(code=2)
        self.assertEqual(self.git("rev-parse", self.branch).strip(), self.base)

    def test_empty_patch_and_invalid_command_are_rejected_without_branches(self):
        for test in ([], "echo unsafe", [""]):
            with self.subTest(test=test):
                self.run_fix(test=test, code=2)
                self.assert_branch_absent()
        self.patch.write_text("")
        self.run_fix(code=2)
        self.assert_branch_absent()

    def test_path_escape_patch_is_rejected(self):
        self.patch.write_text(
            "diff --git a/../outside b/../outside\n--- a/../outside\n+++ b/../outside\n@@ -0,0 +1 @@\n+unexpected\n"
        )
        self.run_fix(code=2)
        self.assertFalse((self.home / "outside").exists())
        self.assert_branch_absent()

    def test_file_deletion_is_outside_supported_patch_scope(self):
        (self.root / "app.py").unlink()
        self.patch.write_text(self.git("diff"))
        self.git("restore", "app.py")
        self.run_fix(code=2)
        self.assert_branch_absent()

    def test_symlink_patch_is_outside_supported_patch_scope(self):
        self.patch.write_text(
            "diff --git a/link b/link\nnew file mode 120000\nindex 0000000..e25f181\n--- /dev/null\n+++ b/link\n@@ -0,0 +1 @@\n+app.py\n\\ No newline at end of file\n"
        )
        self.run_fix(code=2)
        self.assert_branch_absent()

    def test_new_regular_text_files_can_accompany_a_remediation(self):
        with self.patch.open("a") as patch:
            patch.write(
                "diff --git a/regression.txt b/regression.txt\nnew file mode 100644\n--- /dev/null\n+++ b/regression.txt\n@@ -0,0 +1 @@\n+regression\n"
            )
        self.run_fix()
        self.assertEqual(
            self.git("show", self.branch + ":regression.txt"), "regression\n"
        )

    def test_binary_marker_inside_a_text_change_is_not_a_binary_patch(self):
        with self.patch.open("a") as patch:
            patch.write(
                "diff --git a/regression.txt b/regression.txt\nnew file mode 100644\n--- /dev/null\n+++ b/regression.txt\n@@ -0,0 +1 @@\n+GIT binary patch\n"
            )
        self.run_fix()
        self.assertEqual(
            self.git("show", self.branch + ":regression.txt"), "GIT binary patch\n"
        )

    def test_executable_mode_changes_are_rejected(self):
        (self.root / "app.py").chmod(0o755)
        self.patch.write_text(self.git("diff"))
        self.git("restore", "app.py")
        self.run_fix(code=2)
        self.assert_branch_absent()

    def test_commit_hook_cannot_change_the_validated_tree(self):
        hook = self.root / ".git/hooks/pre-commit"
        hook.write_text(
            f"#!{sys.executable}\nfrom pathlib import Path\nimport subprocess\nPath('app.py').write_text('unexpected hook change')\nsubprocess.run(['git','add','app.py'],check=True)\n"
        )
        hook.chmod(0o700)
        self.run_fix(code=2)
        self.assertEqual(self.git("show", "HEAD:app.py"), "eval('input')\n")
        self.assertEqual(len(self.git("worktree", "list").splitlines()), 1)

    def test_commit_hook_cannot_add_unreviewed_commit_history(self):
        hook = self.root / ".git/hooks/post-commit"
        hook.write_text(
            f"#!{sys.executable}\nimport os,subprocess\nif not os.environ.get('HOOK_REENTRY'):\n subprocess.run(['git','commit','--allow-empty','-qm','unexpected extra commit'],check=True,env={{**os.environ,'HOOK_REENTRY':'1'}})\n"
        )
        hook.chmod(0o700)
        self.run_fix(code=2)
        self.assertEqual(self.git("rev-parse", "HEAD").strip(), self.base)

    def test_commit_hook_cannot_add_an_unreviewed_merge_parent(self):
        hidden = self.git(
            "commit-tree",
            self.base + "^{tree}",
            "-p",
            self.base,
            "-m",
            "unreviewed history",
        ).strip()
        hook = self.root / ".git/hooks/post-commit"
        hook.write_text(
            f"#!{sys.executable}\nimport subprocess\ntree=subprocess.run(['git','rev-parse','HEAD^{{tree}}'],check=True,capture_output=True,text=True).stdout.strip()\ncommit=subprocess.run(['git','commit-tree',tree,'-p',{self.base!r},'-p',{hidden!r},'-m','unreviewed merge'],check=True,capture_output=True,text=True).stdout.strip()\nsubprocess.run(['git','update-ref','HEAD',commit],check=True)\n"
        )
        hook.chmod(0o700)
        self.run_fix(code=2)

    def test_replace_refs_cannot_disguise_unreviewed_commit_content(self):
        hook = self.root / ".git/hooks/post-commit"
        hook.write_text(
            f"#!{sys.executable}\n"
            + textwrap.dedent(f"""\
            import pathlib, subprocess
            def git(*args):
                return subprocess.run(['git',*args],check=True,capture_output=True,text=True).stdout.strip()
            reviewed=git('rev-parse','HEAD')
            pathlib.Path('app.py').write_text('UNREVIEWED SECRET CONTENT')
            git('add','app.py')
            tree=git('write-tree')
            actual=git('commit-tree',tree,'-p',{self.base!r},'-m','unreviewed content')
            git('update-ref','HEAD',actual)
            git('replace',actual,reviewed)
            git('read-tree',reviewed)
            git('restore','--worktree','--source',reviewed,'--','app.py')
            """)
        )
        hook.chmod(0o700)
        self.run_fix(code=2)
        self.assertEqual(self.git("rev-parse", "HEAD").strip(), self.base)

    def test_grafted_history_cannot_disguise_an_extra_commit_parent(self):
        hidden = self.git(
            "commit-tree",
            self.base + "^{tree}",
            "-p",
            self.base,
            "-m",
            "unreviewed history",
        ).strip()
        hook = self.root / ".git/hooks/post-commit"
        hook.write_text(
            f"#!{sys.executable}\n"
            + textwrap.dedent(f"""\
            import pathlib, subprocess
            def git(*args):
                return subprocess.run(['git',*args],check=True,capture_output=True,text=True).stdout.strip()
            tree=git('rev-parse','HEAD^{{tree}}')
            actual=git('commit-tree',tree,'-p',{self.base!r},'-p',{hidden!r},'-m','unreviewed merge')
            git('update-ref','HEAD',actual)
            common=pathlib.Path(git('rev-parse','--git-common-dir'))
            (common/'info/grafts').write_text(actual+' '+{self.base!r}+'\\n')
            """)
        )
        hook.chmod(0o700)
        self.run_fix(code=2)

    def test_test_process_timeout_is_not_a_success(self):
        self.run_fix(
            "--timeout",
            "0.5",
            test=[sys.executable, "-c", "import time; time.sleep(30)"],
            code=2,
        )
        self.assert_branch_absent()

    def publication_fixture(self, mode="ok"):
        remote = self.home / "remote.git"
        subprocess.run(
            ["git", "init", "--bare", "-q", str(remote)],
            check=True,
            capture_output=True,
        )
        url = "https://github.com/example/project.git"
        self.git("remote", "add", "origin", url)
        self.git("config", "url." + remote.as_uri() + ".insteadOf", url)
        self.git("push", "-q", "origin", "main")
        gh = self.home / "fake gh"
        gh.write_text(
            f"#!{sys.executable}\nMODE={mode!r}\nLOG={str(self.home / 'gh-args.json')!r}\n"
            + textwrap.dedent("""\
            import json, os, pathlib, sys, time
            pathlib.Path(LOG).write_text(json.dumps(sys.argv[1:]))
            pathlib.Path(LOG + '.env').write_text(json.dumps({'GH_HOST': os.environ.get('GH_HOST')}))
            if MODE == 'fail':
                print('SECRET_CANARY_8379', file=sys.stderr)
                sys.exit(1)
            if MODE == 'hang': time.sleep(30)
            if MODE == 'bad-url':
                print('SECRET_CANARY_8379')
                sys.exit(0)
            print('https://github.com/example/project/pull/123')
            """)
        )
        gh.chmod(0o700)
        body = self.home / "reviewed-pr.md"
        body.write_text("Reviewed remediation and successful targeted checks.")
        args = [
            "--publish",
            "--repo",
            "example/project",
            "--pr-base",
            "main",
            "--title",
            "Fix reviewed finding",
            "--body-file",
            str(body),
            "--gh-executable",
            str(gh),
        ]
        return remote, args

    def test_publication_pushes_a_new_branch_and_creates_a_draft_pr(self):
        remote, args = self.publication_fixture()
        result = self.run_fix(*args)
        self.assertTrue(result["published"])
        self.assertEqual(
            result["pr_url"], "https://github.com/example/project/pull/123"
        )
        remote_head = subprocess.run(
            ["git", "--git-dir", str(remote), "rev-parse", self.branch],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        self.assertEqual(remote_head, result["commit"])
        gh_args = json.loads((self.home / "gh-args.json").read_text())
        self.assertEqual(gh_args[:2], ["pr", "create"])
        self.assertIn("--draft", gh_args)
        self.assertIn("--body-file", gh_args)

    def test_publication_failure_preserves_commit_and_reports_uncertainty(self):
        remote, args = self.publication_fixture(mode="fail")
        result = self.run_fix(*args, code=2)
        self.assertIn("may exist", result.stderr.lower())
        self.git("rev-parse", self.branch)
        subprocess.run(
            ["git", "--git-dir", str(remote), "rev-parse", self.branch],
            check=True,
            capture_output=True,
        )

    def test_publication_rejects_a_different_repository(self):
        remote, args = self.publication_fixture()
        args[args.index("example/project")] = "someone/else"
        self.run_fix(*args, code=2)
        self.assertFalse((self.home / "gh-args.json").exists())
        refs = subprocess.run(
            ["git", "--git-dir", str(remote), "for-each-ref", "--format=%(refname)"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        self.assertNotIn(self.branch, refs)

    def test_publish_requires_complete_reviewed_metadata(self):
        self.run_fix("--publish", code=2)
        self.assert_branch_absent()

    def test_existing_remote_branch_is_never_overwritten(self):
        remote, args = self.publication_fixture()
        self.git("push", "-q", "origin", "main:refs/heads/" + self.branch)
        self.run_fix(*args, code=2)
        actual = subprocess.run(
            ["git", "--git-dir", str(remote), "rev-parse", self.branch],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        self.assertEqual(actual, self.base)
        self.assertFalse((self.home / "gh-args.json").exists())

    def test_publication_never_follows_unrelated_tags(self):
        remote, args = self.publication_fixture()
        self.git("tag", "-a", "private-unrelated-tag", "-m", "not part of remediation")
        self.git("config", "push.followTags", "true")
        self.run_fix(*args)
        tags = subprocess.run(
            ["git", "--git-dir", str(remote), "tag", "--list"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        self.assertEqual(tags, "")

    def test_publication_uses_the_validated_github_host(self):
        _, args = self.publication_fixture()
        with mock.patch.dict(os.environ, {"GH_HOST": "unrelated.enterprise.example"}):
            self.run_fix(*args)
        environment = json.loads((self.home / "gh-args.json.env").read_text())
        self.assertEqual(environment["GH_HOST"], "github.com")

    def test_new_remote_branch_race_does_not_overwrite_another_push(self):
        remote, args = self.publication_fixture()
        hook = self.root / ".git/hooks/pre-push"
        hook.write_text(
            f"#!{sys.executable}\nimport subprocess\nsubprocess.run(['git','--git-dir',{str(remote)!r},'update-ref',{'refs/heads/' + self.branch!r},{self.base!r}],check=True)\n"
        )
        hook.chmod(0o700)
        self.run_fix(*args, code=2)
        actual = subprocess.run(
            ["git", "--git-dir", str(remote), "rev-parse", self.branch],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        self.assertEqual(actual, self.base)
        self.assertFalse((self.home / "gh-args.json").exists())

    def test_separate_origin_push_url_is_rejected(self):
        _, args = self.publication_fixture()
        self.git(
            "config", "remote.origin.pushurl", "https://github.com/another/repo.git"
        )
        self.run_fix(*args, code=2)
        self.assertFalse((self.home / "gh-args.json").exists())

    def test_remote_base_must_be_an_ancestor_of_the_selected_base(self):
        _, args = self.publication_fixture()
        self.git("commit", "--allow-empty", "-qm", "upstream advanced")
        self.git("push", "-q", "origin", "main")
        self.run_fix(*args, "--base", self.base, code=2)
        self.assertFalse((self.home / "gh-args.json").exists())

    def test_unexpected_pr_url_is_not_reported_as_success(self):
        _, args = self.publication_fixture(mode="bad-url")
        self.run_fix(*args, code=2)

    def test_publication_timeout_preserves_the_pushed_commit(self):
        remote, args = self.publication_fixture(mode="hang")
        result = self.run_fix(*args, "--timeout", "4", code=2)
        self.assertIn("may exist", result.stderr.lower())
        subprocess.run(
            ["git", "--git-dir", str(remote), "rev-parse", self.branch],
            check=True,
            capture_output=True,
        )

    def test_publication_interruption_reports_the_remote_uncertainty(self):
        remote, args = self.publication_fixture(mode="hang")
        process = subprocess.Popen(
            self.command(*args),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        def cleanup():
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)

        self.addCleanup(cleanup)
        deadline = time.monotonic() + 10
        while not (self.home / "gh-args.json").exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertTrue((self.home / "gh-args.json").exists())
        process.send_signal(signal.SIGINT)
        stdout, stderr = process.communicate(timeout=5)
        self.assertEqual(process.returncode, 130, stderr)
        self.assertEqual(stdout, "")
        self.assertIn("may exist", stderr.lower())
        self.assertNotIn("SECRET_CANARY_8379", stderr)
        subprocess.run(
            ["git", "--git-dir", str(remote), "rev-parse", self.branch],
            check=True,
            capture_output=True,
        )


if __name__ == "__main__":
    unittest.main()
