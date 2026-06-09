import json
import shutil
import tempfile
import time
from pathlib import Path

from secator.query.utils import parse_report_paths, python_expr_to_mongo, resolve_last_report_path


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


class TestPythonExprToMongo:

    def test_empty_returns_empty(self):
        assert python_expr_to_mongo('') == {}
        assert python_expr_to_mongo(None) == {}

    def test_type_only_no_field(self):
        result = python_expr_to_mongo('domain')
        assert result == {'_type': 'domain'}

    def test_greater_than(self):
        result = python_expr_to_mongo('vulnerability.severity_score > 7')
        assert result == {'_type': 'vulnerability', 'severity_score': {'$gt': 7}}

    def test_greater_than_or_equal(self):
        result = python_expr_to_mongo('vulnerability.severity_score >= 7.5')
        assert result == {'_type': 'vulnerability', 'severity_score': {'$gte': 7.5}}

    def test_less_than(self):
        result = python_expr_to_mongo('port.port < 1024')
        assert result == {'_type': 'port', 'port': {'$lt': 1024}}

    def test_less_than_or_equal(self):
        result = python_expr_to_mongo('port.port <= 443')
        assert result == {'_type': 'port', 'port': {'$lte': 443}}

    def test_equals_string(self):
        result = python_expr_to_mongo("domain.name == 'example.com'")
        assert result == {'_type': 'domain', 'name': 'example.com'}

    def test_equals_double_quoted_string(self):
        result = python_expr_to_mongo('port.state == "open"')
        assert result == {'_type': 'port', 'state': 'open'}

    def test_not_equals(self):
        result = python_expr_to_mongo("port.state != 'closed'")
        assert result == {'_type': 'port', 'state': {'$ne': 'closed'}}

    def test_and_operator(self):
        result = python_expr_to_mongo("port.state == 'open' && port.port < 1024")
        assert result == {'_type': 'port', 'state': 'open', 'port': {'$lt': 1024}}

    def test_or_operator(self):
        result = python_expr_to_mongo('vulnerability.severity_score > 7 || domain')
        assert result == {
            '$or': [
                {'_type': 'vulnerability', 'severity_score': {'$gt': 7}},
                {'_type': 'domain'},
            ]
        }

    def test_regex_match_operator(self):
        result = python_expr_to_mongo("technology.product ~= 'xrdp'")
        assert result == {'_type': 'technology', 'product': {'$regex': 'xrdp'}}

    def test_passthrough_mongo_dict(self):
        query = {'_type': 'vulnerability', 'severity_score': {'$gte': 7}}
        assert python_expr_to_mongo(query) == query

    def test_passthrough_json_string(self):
        import json
        query = {'_type': 'vulnerability', 'severity_score': {'$gte': 7}}
        assert python_expr_to_mongo(json.dumps(query)) == query

    def test_python_and_keyword(self):
        result = python_expr_to_mongo("port.state == 'open' and port.port < 1024")
        assert result == {'_type': 'port', 'state': 'open', 'port': {'$lt': 1024}}

    def test_python_or_keyword(self):
        result = python_expr_to_mongo('vulnerability.severity_score > 7 or domain')
        assert result == {
            '$or': [
                {'_type': 'vulnerability', 'severity_score': {'$gt': 7}},
                {'_type': 'domain'},
            ]
        }

    def test_and_with_quoted_value_containing_and(self):
        result = python_expr_to_mongo("tag.name == 'this and that' and tag.match == 'x'")
        assert result == {'_type': 'tag', 'name': 'this and that', 'match': 'x'}


class TestResolveLastReportPath:

    def _make_report(self, base, workspace, runner_type, report_id):
        """Create a minimal report.json at the expected path."""
        report_dir = Path(base) / workspace / runner_type / str(report_id)
        report_dir.mkdir(parents=True, exist_ok=True)
        report_file = report_dir / 'report.json'
        report_file.write_text(json.dumps({'info': {}, 'results': {}}))
        return report_file

    def setup_method(self):
        self.tmp = tempfile.mkdtemp()

    def teardown_method(self):
        shutil.rmtree(self.tmp)

    def test_none_returns_none(self):
        assert resolve_last_report_path(None, 'ws', self.tmp) is None

    def test_no_last_keyword_passthrough(self):
        assert resolve_last_report_path('scans/5', 'ws', self.tmp) == 'scans/5'
        assert resolve_last_report_path('tasks/3,workflows/2', 'ws', self.tmp) == 'tasks/3,workflows/2'

    def test_tasks_last_resolves_to_highest_id(self):
        self._make_report(self.tmp, 'ws', 'tasks', 1)
        self._make_report(self.tmp, 'ws', 'tasks', 3)
        self._make_report(self.tmp, 'ws', 'tasks', 2)
        result = resolve_last_report_path('tasks/last', 'ws', self.tmp)
        assert result == 'tasks/3'

    def test_workflows_last_resolves_to_highest_id(self):
        self._make_report(self.tmp, 'ws', 'workflows', 0)
        self._make_report(self.tmp, 'ws', 'workflows', 4)
        result = resolve_last_report_path('workflows/last', 'ws', self.tmp)
        assert result == 'workflows/4'

    def test_scans_last_resolves_to_highest_id(self):
        self._make_report(self.tmp, 'ws', 'scans', 7)
        result = resolve_last_report_path('scans/last', 'ws', self.tmp)
        assert result == 'scans/7'

    def test_last_alone_resolves_to_most_recently_modified(self):
        self._make_report(self.tmp, 'ws', 'tasks', 1)
        time.sleep(0.01)
        self._make_report(self.tmp, 'ws', 'workflows', 2)
        result = resolve_last_report_path('last', 'ws', self.tmp)
        assert result == 'workflows/2'

    def test_last_alone_no_reports_returns_none(self):
        result = resolve_last_report_path('last', 'ws', self.tmp)
        assert result is None

    def test_last_with_nonexistent_runner_type_returns_none(self):
        result = resolve_last_report_path('tasks/last', 'ws', self.tmp)
        assert result is None

    def test_non_numeric_dirs_ignored(self):
        self._make_report(self.tmp, 'ws', 'tasks', 5)
        non_numeric = Path(self.tmp) / 'ws' / 'tasks' / 'abc'
        non_numeric.mkdir(parents=True, exist_ok=True)
        result = resolve_last_report_path('tasks/last', 'ws', self.tmp)
        assert result == 'tasks/5'

