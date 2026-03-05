# tests/unit/test_ai_actions.py
"""Tests for AI action handlers - shell execution, queries, decryption."""

import unittest
from unittest.mock import patch, MagicMock

from secator.ai.actions import (
    ActionContext, dispatch_action, _handle_follow_up, _handle_shell,
    _handle_query, _handle_add_finding, _run_runner, _decrypt_dict
)
from secator.output_types import Ai, Error, Info, Warning, Vulnerability, Url


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


class TestHandleFollowUp(unittest.TestCase):
    """Tests for the _handle_follow_up action handler."""

    def test_follow_up_with_reason(self):
        ctx = ActionContext(targets=["t.com"], model="m")
        results = list(_handle_follow_up({"action": "follow_up", "reason": "All scanned"}, ctx))

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], Ai)
        self.assertEqual(results[0].ai_type, "follow_up")
        self.assertEqual(results[0].content, "All scanned")
        self.assertEqual(results[0].extra_data["choices"], [])

    def test_follow_up_default_reason(self):
        ctx = ActionContext(targets=["t.com"], model="m")
        results = list(_handle_follow_up({"action": "follow_up"}, ctx))

        self.assertEqual(results[0].content, "completed")
        self.assertEqual(results[0].extra_data["choices"], [])

    def test_follow_up_with_choices(self):
        ctx = ActionContext(targets=["t.com"], model="m")
        results = list(_handle_follow_up({
            "action": "follow_up",
            "reason": "What next?",
            "choices": ["Scan deeper", "Try SQL injection"],
        }, ctx))

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].ai_type, "follow_up")
        self.assertEqual(results[0].content, "What next?")
        self.assertEqual(results[0].extra_data["choices"], ["Scan deeper", "Try SQL injection"])


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
        ctx = ActionContext(targets=["t.com"], model="m", context={})
        results = list(_handle_query({"action": "query", "query": {}}, ctx))

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], Warning)
        self.assertIn("workspace", results[0].message.lower())

    def test_query_current_scope_no_workspace_ok(self):
        """Scope='current' should work without workspace_id."""
        ctx = ActionContext(
            targets=["t.com"], model="m",
            context={}, scope="current",
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
        ctx = ActionContext(targets=["t.com"], model="m", context={"workspace_id": "ws1"})

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
        ctx = ActionContext(targets=["t.com"], model="m", context={"workspace_id": "ws1"})

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
            context={"workspace_id": "ws1"}, encryptor=encryptor
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
    """Tests for ActionContext.get_query_engine caching and backend selection."""

    @patch('secator.query.QueryEngine')
    def test_caching(self, mock_qe_cls):
        """Same engine instance returned on second call."""
        mock_engine = MagicMock()
        mock_qe_cls.return_value = mock_engine

        ctx = ActionContext(
            targets=["t.com"], model="m",
            context={"workspace_id": "ws1", "drivers": ["mongodb"]}
        )
        engine1 = ctx.get_query_engine()
        engine2 = ctx.get_query_engine()

        self.assertIs(engine1, engine2)
        mock_qe_cls.assert_called_once()

    # -- scope=current: always JsonBackend with in-memory results --

    def test_current_scope_uses_json_backend(self):
        """scope=current always selects JsonBackend, even if drivers has mongodb."""
        from secator.query.json import JsonBackend

        results = [{"_type": "url", "url": "http://a.com"}]
        ctx = ActionContext(
            targets=["t.com"], model="m",
            context={"workspace_id": "ws1", "drivers": ["mongodb"]},
            scope="current", results=results,
        )
        engine = ctx.get_query_engine()

        self.assertIsInstance(engine.backend, JsonBackend)

    def test_current_scope_passes_results(self):
        """scope=current passes results to the backend."""
        results = [{"_type": "url", "url": "http://a.com"}]
        ctx = ActionContext(
            targets=["t.com"], model="m",
            context={"workspace_id": "ws1"},
            scope="current", results=results,
        )
        engine = ctx.get_query_engine()

        self.assertIs(engine.backend._results, results)

    def test_current_scope_does_not_pass_drivers(self):
        """scope=current context should not contain drivers."""
        ctx = ActionContext(
            targets=["t.com"], model="m",
            context={"workspace_id": "ws1", "drivers": ["mongodb"]},
            scope="current", results=[],
        )
        engine = ctx.get_query_engine()

        self.assertEqual(engine.context.get("drivers", []), [])

    def test_current_scope_search_queries_in_memory(self):
        """scope=current queries against in-memory results."""
        results = [
            {"_type": "vulnerability", "name": "SQLi", "severity": "critical"},
            {"_type": "url", "url": "http://a.com"},
            {"_type": "vulnerability", "name": "XSS", "severity": "low"},
        ]
        ctx = ActionContext(
            targets=["t.com"], model="m",
            context={}, scope="current", results=results,
        )
        engine = ctx.get_query_engine()
        found = engine.search({"_type": "vulnerability"})

        self.assertEqual(len(found), 2)
        self.assertTrue(all(r["_type"] == "vulnerability" for r in found))

    # -- scope=workspace + json (no drivers) --

    def test_workspace_scope_json_backend(self):
        """scope=workspace with no drivers selects JsonBackend."""
        from secator.query.json import JsonBackend

        ctx = ActionContext(
            targets=["t.com"], model="m",
            context={"workspace_id": "ws1"},
        )
        engine = ctx.get_query_engine()

        self.assertIsInstance(engine.backend, JsonBackend)

    def test_workspace_scope_json_no_results_preloaded(self):
        """scope=workspace JsonBackend has no pre-loaded results."""
        ctx = ActionContext(
            targets=["t.com"], model="m",
            context={"workspace_id": "ws1"},
        )
        engine = ctx.get_query_engine()

        self.assertIsNone(engine.backend._results)

    # -- scope=workspace + mongodb --

    def test_workspace_scope_mongodb_backend(self):
        """scope=workspace with mongodb driver selects MongoDBBackend."""
        from secator.query.mongodb import MongoDBBackend

        ctx = ActionContext(
            targets=["t.com"], model="m",
            context={"workspace_id": "ws1", "drivers": ["mongodb"]},
        )
        engine = ctx.get_query_engine()

        self.assertIsInstance(engine.backend, MongoDBBackend)

    def test_workspace_scope_mongodb_search(self):
        """scope=workspace mongodb search calls db.findings.find."""
        mock_cursor = MagicMock()
        mock_cursor.__iter__ = MagicMock(return_value=iter([
            {"_id": "abc", "_type": "vulnerability", "name": "SQLi"},
        ]))
        mock_cursor.limit.return_value = mock_cursor

        mock_db = MagicMock()
        mock_db.findings.find.return_value = mock_cursor
        mock_client = MagicMock()
        mock_client.main = mock_db

        ctx = ActionContext(
            targets=["t.com"], model="m",
            context={"workspace_id": "ws1", "drivers": ["mongodb"]},
        )
        engine = ctx.get_query_engine()
        engine.backend._client = mock_client
        found = engine.search({"_type": "vulnerability"}, limit=10)

        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["name"], "SQLi")
        # Verify base query was merged (workspace_id, _tagged)
        call_args = mock_db.findings.find.call_args[0][0]
        self.assertEqual(call_args["_context.workspace_id"], "ws1")
        self.assertTrue(call_args["_tagged"])

    def test_workspace_scope_mongodb_count(self):
        """scope=workspace mongodb count calls db.findings.count_documents."""
        mock_db = MagicMock()
        mock_db.findings.count_documents.return_value = 5
        mock_client = MagicMock()
        mock_client.main = mock_db

        ctx = ActionContext(
            targets=["t.com"], model="m",
            context={"workspace_id": "ws1", "drivers": ["mongodb"]},
        )
        engine = ctx.get_query_engine()
        engine.backend._client = mock_client
        count = engine.count({"_type": "vulnerability"})

        self.assertEqual(count, 5)
        call_args = mock_db.findings.count_documents.call_args[0][0]
        self.assertEqual(call_args["_context.workspace_id"], "ws1")

    # -- scope=workspace + api --

    def test_workspace_scope_api_backend(self):
        """scope=workspace with api driver selects ApiBackend."""
        from secator.query.api import ApiBackend

        ctx = ActionContext(
            targets=["t.com"], model="m",
            context={"workspace_id": "ws1", "drivers": ["api"]},
        )
        engine = ctx.get_query_engine()

        self.assertIsInstance(engine.backend, ApiBackend)

    @patch('secator.query.api.requests.request')
    def test_workspace_scope_api_search(self, mock_request):
        """scope=workspace api search calls POST to search endpoint."""
        mock_response = MagicMock()
        mock_response.json.return_value = [
            {"_type": "vulnerability", "name": "SQLi"},
        ]
        mock_response.raise_for_status = MagicMock()
        mock_request.return_value = mock_response

        ctx = ActionContext(
            targets=["t.com"], model="m",
            context={"workspace_id": "ws1", "drivers": ["api"]},
        )
        engine = ctx.get_query_engine()
        found = engine.search({"_type": "vulnerability"}, limit=10)

        self.assertEqual(len(found), 1)
        mock_request.assert_called_once()
        # Verify POST was used
        call_kwargs = mock_request.call_args
        self.assertEqual(call_kwargs[1]["method"], "POST")

    @patch('secator.query.api.requests.request')
    def test_workspace_scope_api_count(self, mock_request):
        """scope=workspace api count returns total from response."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"total": 42}
        mock_response.raise_for_status = MagicMock()
        mock_request.return_value = mock_response

        ctx = ActionContext(
            targets=["t.com"], model="m",
            context={"workspace_id": "ws1", "drivers": ["api"]},
        )
        engine = ctx.get_query_engine()
        count = engine.count({"_type": "vulnerability"})

        self.assertEqual(count, 42)

    # -- scope=workspace: mongodb takes priority over api --

    def test_workspace_scope_mongodb_priority(self):
        """When both mongodb and api drivers present, mongodb wins."""
        from secator.query.mongodb import MongoDBBackend

        ctx = ActionContext(
            targets=["t.com"], model="m",
            context={"workspace_id": "ws1", "drivers": ["api", "mongodb"]},
        )
        engine = ctx.get_query_engine()

        self.assertIsInstance(engine.backend, MongoDBBackend)


class TestHandleAddFinding(unittest.TestCase):
    """Tests for the _handle_add_finding action handler."""

    def test_add_vulnerability(self):
        ctx = ActionContext(targets=["t.com"], model="m")
        results = list(_handle_add_finding({
            "action": "add_finding",
            "_type": "vulnerability",
            "name": "SQL Injection",
            "severity": "critical",
            "matched_at": "http://t.com/login",
        }, ctx))

        self.assertEqual(len(results), 2)
        self.assertIsInstance(results[0], Vulnerability)
        self.assertEqual(results[0].name, "SQL Injection")
        self.assertEqual(results[0].severity, "critical")
        self.assertEqual(results[0].matched_at, "http://t.com/login")

    def test_add_url(self):
        ctx = ActionContext(targets=["t.com"], model="m")
        results = list(_handle_add_finding({
            "action": "add_finding",
            "_type": "url",
            "url": "http://t.com/admin",
            "status_code": 200,
        }, ctx))

        self.assertEqual(len(results), 2)
        self.assertIsInstance(results[0], Url)
        self.assertEqual(results[0].url, "http://t.com/admin")
        self.assertEqual(results[0].status_code, 200)

    def test_add_finding_unknown_type(self):
        ctx = ActionContext(targets=["t.com"], model="m")
        results = list(_handle_add_finding({
            "action": "add_finding",
            "_type": "nonexistent",
        }, ctx))

        self.assertEqual(len(results), 2)
        self.assertIsInstance(results[0], Warning)
        self.assertIn("nonexistent", results[0].message)

    def test_add_finding_invalid_fields(self):
        ctx = ActionContext(targets=["t.com"], model="m")
        results = list(_handle_add_finding({
            "action": "add_finding",
            "_type": "vulnerability",
            "bad_field": "value",
        }, ctx))

        self.assertEqual(len(results), 2)
        self.assertIsInstance(results[0], Error)

    def test_add_finding_decrypts_values(self):
        encryptor = MagicMock()
        encryptor.decrypt.side_effect = lambda x: x.replace("ENC_", "")
        ctx = ActionContext(targets=["t.com"], model="m", encryptor=encryptor)
        results = list(_handle_add_finding({
            "action": "add_finding",
            "_type": "vulnerability",
            "name": "XSS",
            "matched_at": "ENC_http://t.com/search",
        }, ctx))

        self.assertEqual(len(results), 2)
        self.assertIsInstance(results[0], Vulnerability)
        self.assertEqual(results[0].matched_at, "http://t.com/search")


if __name__ == '__main__':
    unittest.main()
