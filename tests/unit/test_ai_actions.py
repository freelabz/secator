# tests/unit/test_ai_actions.py
"""Tests for AI action handlers - shell execution, queries, decryption."""

import unittest
from unittest.mock import patch, MagicMock

from secator.ai.actions import (
    ActionContext, dispatch_action, _handle_done, _handle_shell,
    _handle_query, _run_runner, _decrypt_dict
)
from secator.output_types import Ai, Error, Info, Warning


class TestDecryptDict(unittest.TestCase):
    """Tests for _decrypt_dict recursive decryption."""

    def test_decrypt_string_values(self):
        encryptor = MagicMock()
        encryptor.decrypt.side_effect = lambda x: x.upper()

        result = _decrypt_dict({"host": "example.com", "port": "443"}, encryptor)

        self.assertEqual(result["host"], "EXAMPLE.COM")
        self.assertEqual(result["port"], "443")

    def test_decrypt_nested_dict(self):
        encryptor = MagicMock()
        encryptor.decrypt.side_effect = lambda x: x.upper()

        result = _decrypt_dict({
            "outer": {"inner": "value"}
        }, encryptor)

        self.assertEqual(result["outer"]["inner"], "VALUE")

    def test_decrypt_list_values(self):
        encryptor = MagicMock()
        encryptor.decrypt.side_effect = lambda x: x.upper()

        result = _decrypt_dict({
            "hosts": ["a.com", "b.com"],
        }, encryptor)

        self.assertEqual(result["hosts"], ["A.COM", "B.COM"])

    def test_decrypt_mixed_list(self):
        encryptor = MagicMock()
        encryptor.decrypt.side_effect = lambda x: x.upper()

        result = _decrypt_dict({
            "items": ["text", 42, {"key": "val"}],
        }, encryptor)

        self.assertEqual(result["items"][0], "TEXT")
        self.assertEqual(result["items"][1], 42)
        self.assertEqual(result["items"][2]["key"], "VAL")

    def test_decrypt_non_string_values(self):
        encryptor = MagicMock()

        result = _decrypt_dict({
            "count": 5,
            "active": True,
            "score": 3.14,
        }, encryptor)

        self.assertEqual(result["count"], 5)
        self.assertEqual(result["active"], True)
        self.assertEqual(result["score"], 3.14)
        encryptor.decrypt.assert_not_called()


class TestHandleDone(unittest.TestCase):
    """Tests for the _handle_done action handler."""

    def test_done_with_reason(self):
        ctx = ActionContext(targets=["t.com"], model="m")
        results = list(_handle_done({"action": "done", "reason": "All scanned"}, ctx))

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], Ai)
        self.assertEqual(results[0].ai_type, "stopped")
        self.assertEqual(results[0].content, "All scanned")

    def test_done_default_reason(self):
        ctx = ActionContext(targets=["t.com"], model="m")
        results = list(_handle_done({"action": "done"}, ctx))

        self.assertEqual(results[0].content, "completed")


class TestHandleShell(unittest.TestCase):
    """Tests for the _handle_shell action handler."""

    def test_shell_dry_run(self):
        ctx = ActionContext(targets=["t.com"], model="m", dry_run=True)
        results = list(_handle_shell({"action": "shell", "command": "whoami"}, ctx))

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], Info)
        self.assertIn("DRY RUN", results[0].message)
        self.assertIn("whoami", results[0].message)

    @patch('secator.ai.actions.subprocess.run')
    def test_shell_execution(self, mock_run):
        mock_run.return_value = MagicMock(stdout="root\n", stderr="")
        ctx = ActionContext(targets=["t.com"], model="m")

        results = list(_handle_shell({"action": "shell", "command": "whoami"}, ctx))

        self.assertEqual(len(results), 2)
        # First: the command being run
        self.assertIsInstance(results[0], Ai)
        self.assertEqual(results[0].ai_type, "shell")
        self.assertEqual(results[0].content, "whoami")
        # Second: the output
        self.assertIsInstance(results[1], Ai)
        self.assertEqual(results[1].ai_type, "shell_output")
        self.assertIn("root", results[1].content)

    @patch('secator.ai.actions.subprocess.run')
    def test_shell_stderr(self, mock_run):
        mock_run.return_value = MagicMock(stdout="", stderr="error msg")
        ctx = ActionContext(targets=["t.com"], model="m")

        results = list(_handle_shell({"action": "shell", "command": "bad"}, ctx))

        self.assertEqual(results[1].content, "error msg")

    @patch('secator.ai.actions.subprocess.run')
    def test_shell_no_output(self, mock_run):
        mock_run.return_value = MagicMock(stdout="", stderr="")
        ctx = ActionContext(targets=["t.com"], model="m")

        results = list(_handle_shell({"action": "shell", "command": "true"}, ctx))

        self.assertEqual(results[1].content, "(no output)")

    @patch('secator.ai.actions.subprocess.run')
    def test_shell_exception(self, mock_run):
        mock_run.side_effect = Exception("Command timed out")
        ctx = ActionContext(targets=["t.com"], model="m")

        results = list(_handle_shell({"action": "shell", "command": "slow"}, ctx))

        # shell Ai + Error
        self.assertEqual(len(results), 2)
        self.assertIsInstance(results[1], Error)
        self.assertIn("failed", results[1].message)

    def test_shell_decrypts_command(self):
        encryptor = MagicMock()
        encryptor.decrypt.side_effect = lambda x: x.replace("ENCRYPTED", "real-host")
        ctx = ActionContext(targets=["t.com"], model="m", encryptor=encryptor, dry_run=True)

        results = list(_handle_shell(
            {"action": "shell", "command": "nmap ENCRYPTED"},
            ctx
        ))

        self.assertIn("real-host", results[0].message)
        encryptor.decrypt.assert_called_once_with("nmap ENCRYPTED")


class TestHandleQuery(unittest.TestCase):
    """Tests for the _handle_query action handler."""

    def test_query_no_workspace(self):
        ctx = ActionContext(targets=["t.com"], model="m", workspace_id=None)
        results = list(_handle_query({"action": "query", "query": {}}, ctx))

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], Warning)
        self.assertIn("workspace", results[0].message.lower())

    def test_query_current_scope_no_workspace_ok(self):
        """Scope='current' should work without workspace_id."""
        ctx = ActionContext(
            targets=["t.com"], model="m",
            workspace_id=None, scope="current",
            results=[{"host": "a.com", "port": 80}]
        )

        with patch.object(ctx, 'get_query_engine') as mock_get_engine:
            mock_engine = MagicMock()
            mock_engine.search.return_value = [{"host": "a.com", "port": 80}]
            mock_get_engine.return_value = mock_engine

            results = list(_handle_query({"action": "query", "query": {"host": "a.com"}}, ctx))

        # Should have Ai + result dict (no warning)
        ai_results = [r for r in results if isinstance(r, Ai)]
        self.assertEqual(len(ai_results), 1)
        self.assertEqual(ai_results[0].ai_type, "query")

    @patch('secator.ai.actions.ActionContext.get_query_engine')
    def test_query_success(self, mock_get_engine):
        mock_engine = MagicMock()
        mock_engine.search.return_value = [
            {"host": "a.com", "port": 80, "_type": "port"},
            {"host": "b.com", "port": 443, "_type": "port"},
        ]
        mock_get_engine.return_value = mock_engine
        ctx = ActionContext(targets=["t.com"], model="m", workspace_id="ws1")

        results = list(_handle_query(
            {"action": "query", "query": {"port": 80}, "limit": 10},
            ctx
        ))

        # Ai header + 2 result dicts
        ai_results = [r for r in results if isinstance(r, Ai)]
        self.assertEqual(len(ai_results), 1)
        self.assertEqual(ai_results[0].extra_data["results"], 2)
        mock_engine.search.assert_called_once_with({"port": 80}, limit=10)

    @patch('secator.ai.actions.ActionContext.get_query_engine')
    def test_query_failure(self, mock_get_engine):
        mock_engine = MagicMock()
        mock_engine.search.side_effect = Exception("DB error")
        mock_get_engine.return_value = mock_engine
        ctx = ActionContext(targets=["t.com"], model="m", workspace_id="ws1")

        results = list(_handle_query(
            {"action": "query", "query": {}},
            ctx
        ))

        errors = [r for r in results if isinstance(r, Error)]
        self.assertEqual(len(errors), 1)

    def test_query_decrypts_filter(self):
        encryptor = MagicMock()
        encryptor.decrypt.side_effect = lambda x: x.replace("ENC_", "")
        ctx = ActionContext(
            targets=["t.com"], model="m",
            workspace_id="ws1", encryptor=encryptor
        )

        with patch.object(ctx, 'get_query_engine') as mock_get_engine:
            mock_engine = MagicMock()
            mock_engine.search.return_value = []
            mock_get_engine.return_value = mock_engine

            list(_handle_query(
                {"action": "query", "query": {"host": "ENC_example.com"}},
                ctx
            ))

        # Verify the decrypted value was used
        mock_engine.search.assert_called_once()
        call_args = mock_engine.search.call_args[0][0]
        self.assertEqual(call_args["host"], "example.com")


class TestRunRunner(unittest.TestCase):
    """Tests for the _run_runner function."""

    def test_run_runner_dry_run_task(self):
        ctx = ActionContext(targets=["t.com"], model="m", dry_run=True)
        action = {"action": "task", "name": "nmap", "targets": ["192.168.1.1"]}

        results = list(_run_runner(action, ctx, "task"))

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], Info)
        self.assertIn("DRY RUN", results[0].message)
        self.assertIn("nmap", results[0].message)

    def test_run_runner_dry_run_workflow(self):
        ctx = ActionContext(targets=["t.com"], model="m", dry_run=True)
        action = {"action": "workflow", "name": "host_recon", "targets": ["t.com"]}

        results = list(_run_runner(action, ctx, "workflow"))

        self.assertIn("DRY RUN", results[0].message)
        self.assertIn("host_recon", results[0].message)

    def test_run_runner_decrypts_targets(self):
        encryptor = MagicMock()
        encryptor.decrypt.side_effect = lambda x: x.replace("ENC_", "")
        ctx = ActionContext(targets=["t.com"], model="m", encryptor=encryptor, dry_run=True)
        action = {"action": "task", "name": "nmap", "targets": ["ENC_10.0.0.1"]}

        results = list(_run_runner(action, ctx, "task"))

        self.assertIn("10.0.0.1", results[0].message)

    def test_run_runner_uses_ctx_targets_as_default(self):
        ctx = ActionContext(targets=["default.com"], model="m", dry_run=True)
        action = {"action": "task", "name": "nmap"}  # no targets in action

        results = list(_run_runner(action, ctx, "task"))

        self.assertIn("default.com", results[0].message)


class TestGetQueryEngine(unittest.TestCase):
    """Tests for ActionContext.get_query_engine caching."""

    @patch('secator.query.QueryEngine')
    def test_get_query_engine_caching(self, mock_qe_cls):
        """Same engine instance returned on second call."""
        mock_engine = MagicMock()
        mock_qe_cls.return_value = mock_engine

        ctx = ActionContext(
            targets=["t.com"], model="m",
            workspace_id="ws1", drivers=["mongodb"]
        )
        engine1 = ctx.get_query_engine()
        engine2 = ctx.get_query_engine()

        self.assertIs(engine1, engine2)
        mock_qe_cls.assert_called_once()

    @patch('secator.query.QueryEngine')
    def test_get_query_engine_current_scope(self, mock_qe_cls):
        """Current scope passes results to QueryEngine context."""
        mock_engine = MagicMock()
        mock_qe_cls.return_value = mock_engine

        results = [{"host": "a.com"}]
        ctx = ActionContext(
            targets=["t.com"], model="m",
            workspace_id="ws1", scope="current",
            results=results, scan_id="scan123"
        )
        ctx.get_query_engine()

        call_kwargs = mock_qe_cls.call_args
        context = call_kwargs[1]["context"] if "context" in call_kwargs[1] else call_kwargs[0][1]
        self.assertEqual(context["results"], results)
        self.assertEqual(context["scan_id"], "scan123")


if __name__ == '__main__':
    unittest.main()
