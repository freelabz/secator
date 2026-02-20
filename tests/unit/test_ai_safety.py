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
