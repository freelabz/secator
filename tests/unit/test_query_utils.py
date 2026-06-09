from unittest.mock import patch

from secator.query.utils import parse_report_paths, python_expr_to_mongo, validate_query_fields


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

    def test_in_operator_integers(self):
        result = python_expr_to_mongo("url.status_code in [200,304]")
        assert result == {'_type': 'url', 'status_code': {'$in': [200, 304]}}

    def test_in_operator_strings(self):
        result = python_expr_to_mongo("vulnerability.severity in ['high', 'critical']")
        assert result == {'_type': 'vulnerability', 'severity': {'$in': ['high', 'critical']}}

    def test_in_operator_double_quoted_strings(self):
        result = python_expr_to_mongo('vulnerability.severity in ["high", "critical"]')
        assert result == {'_type': 'vulnerability', 'severity': {'$in': ['high', 'critical']}}

    def test_in_operator_multiple_values(self):
        result = python_expr_to_mongo("port.port in [80, 443, 8080]")
        assert result == {'_type': 'port', 'port': {'$in': [80, 443, 8080]}}

    def test_in_operator_with_and(self):
        result = python_expr_to_mongo("url.status_code in [200, 304] && url.path == '/api'")
        assert result == {'_type': 'url', 'status_code': {'$in': [200, 304]}, 'path': '/api'}

    def test_in_operator_with_python_and(self):
        result = python_expr_to_mongo(
            "vulnerability.severity in ['high', 'critical'] and vulnerability.severity_score > 7"
        )
        assert result == {
            '_type': 'vulnerability',
            'severity': {'$in': ['high', 'critical']},
            'severity_score': {'$gt': 7},
        }

    def test_in_operator_floats(self):
        result = python_expr_to_mongo("item.score in [1.5, 2.5, 3.0]")
        assert result == {'_type': 'item', 'score': {'$in': [1.5, 2.5, 3.0]}}


class TestValidateQueryFields:

    def test_none_returns_none(self):
        assert validate_query_fields(None) is None

    def test_empty_dict_returns_empty(self):
        assert validate_query_fields({}) == {}

    def test_valid_field_passes_through(self):
        q = {'_type': 'vulnerability', 'severity': {'$regex': 'high'}}
        assert validate_query_fields(q) == q

    def test_invalid_field_removed_with_warning(self):
        q = {'_type': 'technology', 'name': {'$regex': '(HSTS|php)'}}
        with patch('secator.query.utils.console') as mock_console:
            result = validate_query_fields(q)
        assert result == {'_type': 'technology'}
        mock_console.print.assert_called_once()
        warning_obj = mock_console.print.call_args[0][0]
        assert 'name' in warning_obj.message
        assert 'technology' in warning_obj.message
        assert 'product' in warning_obj.message  # one of the available fields

    def test_or_validates_each_fragment(self):
        q = {
            '$or': [
                {'_type': 'url', 'status_code': {'$ne': 200}},
                {'_type': 'technology', 'name': {'$regex': '(HSTS|php)'}},
            ]
        }
        with patch('secator.query.utils.console') as mock_console:
            result = validate_query_fields(q)
        assert result == {
            '$or': [
                {'_type': 'url', 'status_code': {'$ne': 200}},
                {'_type': 'technology'},
            ]
        }
        mock_console.print.assert_called_once()

    def test_and_validates_each_fragment(self):
        q = {
            '$and': [
                {'_context.scan_id': '5'},
                {'_type': 'technology', 'name': {'$regex': 'php'}},
            ]
        }
        with patch('secator.query.utils.console') as mock_console:
            result = validate_query_fields(q)
        assert result == {
            '$and': [
                {'_context.scan_id': '5'},
                {'_type': 'technology'},
            ]
        }
        mock_console.print.assert_called_once()

    def test_unknown_type_passes_through(self):
        q = {'_type': 'unknown_type', 'foo': 'bar'}
        assert validate_query_fields(q) == q

    def test_no_type_passes_through(self):
        q = {'_context.scan_id': '5'}
        assert validate_query_fields(q) == q

    def test_internal_fields_pass_through(self):
        q = {'_type': 'url', '_context': {'scan_id': '5'}, '_timestamp': {'$gte': 0}}
        assert validate_query_fields(q) == q

    def test_nested_extra_data_field_passes_through(self):
        q = {'_type': 'url', 'extra_data.custom': 'value'}
        assert validate_query_fields(q) == q

    def test_multiple_invalid_fields_all_warned(self):
        q = {'_type': 'technology', 'name': 'php', 'bogus': 'x'}
        with patch('secator.query.utils.console') as mock_console:
            result = validate_query_fields(q)
        assert result == {'_type': 'technology'}
        assert mock_console.print.call_count == 2

    def test_valid_url_status_code(self):
        q = {'_type': 'url', 'status_code': {'$ne': 200}}
        assert validate_query_fields(q) == q

    def test_valid_vulnerability_cvss_score(self):
        q = {'_type': 'vulnerability', 'cvss_score': {'$gt': 7}}
        assert validate_query_fields(q) == q

