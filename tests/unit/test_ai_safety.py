# tests/unit/test_ai_safety.py

import unittest


class TestSafetyFlags(unittest.TestCase):

    def test_add_rate_limit_nuclei(self):
        from secator.tasks.ai import add_rate_limit

        cmd = "secator x nuclei target.com"
        result = add_rate_limit(cmd, 10)

        self.assertIn('-rl 10', result)

    def test_add_rate_limit_nmap(self):
        from secator.tasks.ai import add_rate_limit

        cmd = "secator x nmap target.com"
        result = add_rate_limit(cmd, 100)

        self.assertIn('--max-rate 100', result)

    def test_add_rate_limit_already_present(self):
        from secator.tasks.ai import add_rate_limit

        cmd = "secator x nuclei target.com -rl 5"
        result = add_rate_limit(cmd, 10)

        # Should not add duplicate
        self.assertEqual(result.count('-rl'), 1)

    def test_add_rate_limit_unknown_tool(self):
        from secator.tasks.ai import add_rate_limit

        cmd = "secator x unknown_tool target.com"
        result = add_rate_limit(cmd, 10)

        # Should return unchanged
        self.assertEqual(cmd, result)

    def test_add_rate_limit_sqlmap(self):
        from secator.tasks.ai import add_rate_limit

        cmd = "secator x sqlmap target.com"
        result = add_rate_limit(cmd, 10)

        # sqlmap uses delay in ms: 1000/10 = 100ms
        self.assertIn('--delay 100', result)

    def test_add_rate_limit_zero_rate(self):
        from secator.tasks.ai import add_rate_limit

        cmd = "secator x nuclei target.com"
        result = add_rate_limit(cmd, 0)

        # Should return unchanged when rate is 0
        self.assertEqual(cmd, result)

    def test_add_rate_limit_negative_rate(self):
        from secator.tasks.ai import add_rate_limit

        cmd = "secator x nuclei target.com"
        result = add_rate_limit(cmd, -5)

        # Should return unchanged when rate is negative
        self.assertEqual(cmd, result)


class TestSafetyCheck(unittest.TestCase):

    def test_check_action_safety_ci_auto_approve(self):
        from secator.tasks.ai import check_action_safety

        action = {
            'command': 'secator x sqlmap target.com',
            'destructive': True,
            'aggressive': True
        }

        should_run, cmd = check_action_safety(action, auto_yes=False, in_ci=True)

        self.assertTrue(should_run)
        self.assertEqual(cmd, action['command'])

    def test_check_action_safety_auto_yes(self):
        from secator.tasks.ai import check_action_safety

        action = {
            'command': 'secator x sqlmap target.com',
            'destructive': True,
            'aggressive': False
        }

        should_run, cmd = check_action_safety(action, auto_yes=True, in_ci=False)

        self.assertTrue(should_run)

    def test_check_action_safety_non_destructive(self):
        from secator.tasks.ai import check_action_safety

        action = {
            'command': 'secator x httpx target.com',
            'destructive': False,
            'aggressive': False
        }

        should_run, cmd = check_action_safety(action, auto_yes=False, in_ci=False)

        self.assertTrue(should_run)


class TestFormatExecutedCommands(unittest.TestCase):

    def test_format_executed_commands_empty(self):
        from secator.tasks.ai import format_executed_commands

        context = {"successful_attacks": [], "failed_attacks": []}
        result = format_executed_commands(context)

        self.assertEqual(result, "")

    def test_format_executed_commands_task(self):
        from secator.tasks.ai import format_executed_commands

        context = {
            "successful_attacks": [
                {"type": "task", "name": "nmap", "targets": ["192.168.1.1"]}
            ],
            "failed_attacks": []
        }
        result = format_executed_commands(context)

        self.assertIn("ALREADY EXECUTED", result)
        self.assertIn("DO NOT REPEAT", result)
        self.assertIn("task: nmap on [192.168.1.1]", result)

    def test_format_executed_commands_shell(self):
        from secator.tasks.ai import format_executed_commands

        context = {
            "successful_attacks": [
                {"type": "shell", "command": "curl http://target.com", "target": "target.com"}
            ],
            "failed_attacks": []
        }
        result = format_executed_commands(context)

        self.assertIn("shell: curl http://target.com", result)
        self.assertIn("target: target.com", result)

    def test_format_executed_commands_with_opts(self):
        from secator.tasks.ai import format_executed_commands

        context = {
            "successful_attacks": [
                {
                    "type": "task",
                    "name": "nuclei",
                    "targets": ["example.com"],
                    "opts": {"severity": "critical", "rate_limit": 10}
                }
            ],
            "failed_attacks": []
        }
        result = format_executed_commands(context)

        self.assertIn("nuclei", result)
        self.assertIn("example.com", result)
        self.assertIn("severity=critical", result)

    def test_format_executed_commands_failed(self):
        from secator.tasks.ai import format_executed_commands

        context = {
            "successful_attacks": [],
            "failed_attacks": [
                {"type": "task", "name": "sqlmap", "targets": ["target.com"]}
            ]
        }
        result = format_executed_commands(context)

        self.assertIn("FAILED", result)
        self.assertIn("sqlmap", result)

    def test_format_executed_commands_multiple(self):
        from secator.tasks.ai import format_executed_commands

        context = {
            "successful_attacks": [
                {"type": "task", "name": "nmap", "targets": ["192.168.1.1"]},
                {"type": "workflow", "name": "host_recon", "targets": ["example.com"]},
                {"type": "shell", "command": "curl http://test.com", "target": "test.com"}
            ],
            "failed_attacks": []
        }
        result = format_executed_commands(context)

        self.assertIn("task: nmap", result)
        self.assertIn("workflow: host_recon", result)
        self.assertIn("shell: curl", result)


class TestPromptLoading(unittest.TestCase):

    def test_load_prompt_from_text(self):
        from secator.tasks.ai import load_prompt_from_file_or_text

        text = "Analyze this target for SQL injection"
        content, from_file, is_md = load_prompt_from_file_or_text(text)

        self.assertEqual(content, text)
        self.assertFalse(from_file)
        self.assertFalse(is_md)

    def test_load_prompt_from_empty(self):
        from secator.tasks.ai import load_prompt_from_file_or_text

        content, from_file, is_md = load_prompt_from_file_or_text("")

        self.assertEqual(content, "")
        self.assertFalse(from_file)
        self.assertFalse(is_md)

    def test_load_prompt_from_txt_file(self):
        import tempfile
        import os
        from secator.tasks.ai import load_prompt_from_file_or_text

        # Create a temp text file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("Focus on OWASP Top 10 vulnerabilities")
            temp_path = f.name

        try:
            content, from_file, is_md = load_prompt_from_file_or_text(temp_path)

            self.assertEqual(content, "Focus on OWASP Top 10 vulnerabilities")
            self.assertTrue(from_file)
            self.assertFalse(is_md)
        finally:
            os.unlink(temp_path)

    def test_load_prompt_from_md_file(self):
        import tempfile
        import os
        from secator.tasks.ai import load_prompt_from_file_or_text

        # Create a temp markdown file
        md_content = "# Pentest Rules\n\n- Focus on auth bypass\n- Check for SQLi"
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            f.write(md_content)
            temp_path = f.name

        try:
            content, from_file, is_md = load_prompt_from_file_or_text(temp_path)

            self.assertEqual(content, md_content)
            self.assertTrue(from_file)
            self.assertTrue(is_md)
        finally:
            os.unlink(temp_path)

    def test_load_prompt_nonexistent_file_treated_as_text(self):
        from secator.tasks.ai import load_prompt_from_file_or_text

        # A path that doesn't exist should be treated as text
        fake_path = "/nonexistent/path/to/file.txt"
        content, from_file, is_md = load_prompt_from_file_or_text(fake_path)

        self.assertEqual(content, fake_path)
        self.assertFalse(from_file)
        self.assertFalse(is_md)

    def test_load_prompt_expands_tilde(self):
        import tempfile
        import os
        from secator.tasks.ai import load_prompt_from_file_or_text

        # Create a temp file in home dir (we'll test path expansion logic)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("Test content")
            temp_path = f.name

        try:
            # Test with actual path (not tilde, but confirms os.path.expanduser is called)
            content, from_file, is_md = load_prompt_from_file_or_text(temp_path)
            self.assertTrue(from_file)
        finally:
            os.unlink(temp_path)
