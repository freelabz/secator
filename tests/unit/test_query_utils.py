from secator.query.utils import parse_report_paths


class TestParseReportPaths:

    def test_empty_returns_empty_dict(self):
        assert parse_report_paths('') == {}
        assert parse_report_paths(None) == {}

    def test_single_scan(self):
        result = parse_report_paths('scans/5')
        assert result == {'_context.scan_id': '5'}

    def test_single_task(self):
        result = parse_report_paths('tasks/3')
        assert result == {'_context.task_id': '3'}

    def test_single_workflow(self):
        result = parse_report_paths('workflows/4')
        assert result == {'_context.workflow_id': '4'}

    def test_multiple_paths_uses_or(self):
        result = parse_report_paths('scans/5,tasks/3')
        assert result == {
            '$or': [
                {'_context.scan_id': '5'},
                {'_context.task_id': '3'},
            ]
        }

    def test_three_paths(self):
        result = parse_report_paths('scans/5,tasks/3,workflows/4')
        assert result == {
            '$or': [
                {'_context.scan_id': '5'},
                {'_context.task_id': '3'},
                {'_context.workflow_id': '4'},
            ]
        }

    def test_uuid_value(self):
        result = parse_report_paths('scans/abc-123-def')
        assert result == {'_context.scan_id': 'abc-123-def'}
