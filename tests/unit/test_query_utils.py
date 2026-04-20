from secator.query.utils import parse_report_paths, python_expr_to_mongo, _normalize_field_path


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

    def test_get_method_normalization(self):
        result = python_expr_to_mongo("tag.extra_data.get('product') == 'Apache'")
        assert result == {'_type': 'tag', 'extra_data.product': 'Apache'}

    def test_get_method_double_quotes(self):
        result = python_expr_to_mongo('tag.extra_data.get("product") == "Apache"')
        assert result == {'_type': 'tag', 'extra_data.product': 'Apache'}

    def test_full_issue_query(self):
        result = python_expr_to_mongo(
            "tag.name == 'technology' and tag.extra_data.get('product') == 'Apache HTTP Server'"
        )
        assert result == {'_type': 'tag', 'name': 'technology', 'extra_data.product': 'Apache HTTP Server'}


class TestNormalizeFieldPath:

    def test_get_single_quotes(self):
        assert _normalize_field_path("extra_data.get('product')") == 'extra_data.product'

    def test_get_double_quotes(self):
        assert _normalize_field_path('extra_data.get("product")') == 'extra_data.product'

    def test_nested_get(self):
        assert _normalize_field_path("a.b.get('c')") == 'a.b.c'

    def test_no_get(self):
        assert _normalize_field_path('extra_data.product') == 'extra_data.product'

    def test_get_non_identifier_key(self):
        assert _normalize_field_path("extra_data.get('http-title')") == 'extra_data.http-title'

    def test_get_with_spaces(self):
        assert _normalize_field_path("extra_data.get( 'product' )") == 'extra_data.product'
