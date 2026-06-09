from secator.query.utils import (
    expand_runner_paths,
    parse_report_paths,
    python_expr_to_mongo,
    validate_query_fields,
    query_has_type_constraint,
)


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


class TestQueryHasTypeConstraint:

    def test_empty_query(self):
        assert query_has_type_constraint({}) is False

    def test_no_type_constraint(self):
        assert query_has_type_constraint({'_timestamp': {'$gte': 123}}) is False

    def test_top_level_type(self):
        assert query_has_type_constraint({'_type': 'target'}) is True

    def test_type_with_field(self):
        assert query_has_type_constraint({'_type': 'port', 'port': {'$lt': 1024}}) is True

    def test_type_inside_or(self):
        query = {'$or': [{'_type': 'vulnerability'}, {'_type': 'target'}]}
        assert query_has_type_constraint(query) is True

    def test_type_inside_and(self):
        query = {'$and': [{'_context.scan_id': '5'}, {'_type': 'target'}]}
        assert query_has_type_constraint(query) is True

    def test_nested_without_type(self):
        query = {'$or': [{'_context.scan_id': '5'}, {'_context.task_id': '3'}]}
        assert query_has_type_constraint(query) is False


class TestExpandRunnerPaths:

    def test_single_path(self):
        refs, errors = expand_runner_paths(['tasks/23'])
        assert refs == [('tasks', 'task', '23')]
        assert errors == []

    def test_string_input(self):
        refs, errors = expand_runner_paths('tasks/23')
        assert refs == [('tasks', 'task', '23')]
        assert errors == []

    def test_space_separated_tokens(self):
        refs, errors = expand_runner_paths(['tasks/23', 'tasks/24', 'workflows/21'])
        assert refs == [
            ('tasks', 'task', '23'),
            ('tasks', 'task', '24'),
            ('workflows', 'workflow', '21'),
        ]
        assert errors == []

    def test_comma_separated_single_token(self):
        refs, errors = expand_runner_paths(['tasks/23,tasks/24,workflows/21'])
        assert refs == [
            ('tasks', 'task', '23'),
            ('tasks', 'task', '24'),
            ('workflows', 'workflow', '21'),
        ]
        assert errors == []

    def test_range_expansion(self):
        refs, errors = expand_runner_paths(['tasks/136-140'])
        assert refs == [('tasks', 'task', str(n)) for n in range(136, 141)]
        assert errors == []

    def test_mixed_ranges_and_comma(self):
        refs, errors = expand_runner_paths(['tasks/136-140,workflows/10-12'])
        assert refs == (
            [('tasks', 'task', str(n)) for n in range(136, 141)]
            + [('workflows', 'workflow', str(n)) for n in range(10, 13)]
        )
        assert errors == []

    def test_single_element_range(self):
        refs, errors = expand_runner_paths(['tasks/5-5'])
        assert refs == [('tasks', 'task', '5')]
        assert errors == []

    def test_singular_type_normalized(self):
        refs, errors = expand_runner_paths(['task/7', 'scan/2'])
        assert refs == [('tasks', 'task', '7'), ('scans', 'scan', '2')]
        assert errors == []

    def test_dedupe_preserves_order(self):
        refs, errors = expand_runner_paths(['tasks/23', 'tasks/23', 'tasks/22-24'])
        assert refs == [
            ('tasks', 'task', '23'),
            ('tasks', 'task', '22'),
            ('tasks', 'task', '24'),
        ]
        assert errors == []

    def test_invalid_type(self):
        refs, errors = expand_runner_paths(['foo/1'])
        assert refs == []
        assert len(errors) == 1
        assert 'Invalid runner type' in errors[0]

    def test_missing_slash(self):
        refs, errors = expand_runner_paths(['tasks23'])
        assert refs == []
        assert 'Expected format' in errors[0]

    def test_non_numeric_id(self):
        refs, errors = expand_runner_paths(['tasks/abc'])
        assert refs == []
        assert 'Must be numeric' in errors[0]

    def test_reversed_range(self):
        refs, errors = expand_runner_paths(['tasks/140-136'])
        assert refs == []
        assert 'Start must be <= end' in errors[0]

    def test_non_numeric_range(self):
        refs, errors = expand_runner_paths(['tasks/1-x'])
        assert refs == []
        assert 'Both bounds must be numeric' in errors[0]

    def test_valid_and_invalid_mixed(self):
        refs, errors = expand_runner_paths(['tasks/23', 'bad/x', 'workflows/2'])
        assert refs == [('tasks', 'task', '23'), ('workflows', 'workflow', '2')]
        assert len(errors) == 1
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
        # When ALL user-specified fields are invalid, the fragment is dropped entirely
        # (returning {} rather than {'_type': 'technology'} which would match everything).
        from secator.rich import console
        console.export_text(clear=True)
        q = {'_type': 'technology', 'name': {'$regex': '(HSTS|php)'}}
        result = validate_query_fields(q)
        assert result == {}
        recorded = console.export_text()
        assert "Field 'name' does not exist on type 'technology'" in recorded
        assert 'product' in recorded  # one of the available fields

    def test_or_validates_each_fragment(self):
        # The technology fragment has no valid user fields, so it is dropped from $or.
        # The $or collapses to a single item, which is unwrapped.
        from secator.rich import console
        console.export_text(clear=True)
        q = {
            '$or': [
                {'_type': 'url', 'status_code': {'$ne': 200}},
                {'_type': 'technology', 'name': {'$regex': '(HSTS|php)'}},
            ]
        }
        result = validate_query_fields(q)
        assert result == {'_type': 'url', 'status_code': {'$ne': 200}}
        recorded = console.export_text()
        assert "Field 'name' does not exist on type 'technology'" in recorded

    def test_or_with_partial_invalid_fields(self):
        # When one fragment has some valid and some invalid fields, only the invalid
        # field is removed; the fragment itself is kept.
        from secator.rich import console
        console.export_text(clear=True)
        q = {
            '$or': [
                {'_type': 'url', 'status_code': {'$ne': 200}},
                {'_type': 'technology', 'product': 'nginx', 'name': 'bogus'},
            ]
        }
        result = validate_query_fields(q)
        assert result == {
            '$or': [
                {'_type': 'url', 'status_code': {'$ne': 200}},
                {'_type': 'technology', 'product': 'nginx'},
            ]
        }
        recorded = console.export_text()
        assert "Field 'name' does not exist on type 'technology'" in recorded

    def test_and_validates_each_fragment(self):
        # The technology fragment (all user fields invalid) is dropped from $and.
        # The $and collapses to a single item, which is unwrapped.
        from secator.rich import console
        console.export_text(clear=True)
        q = {
            '$and': [
                {'_context.scan_id': '5'},
                {'_type': 'technology', 'name': {'$regex': 'php'}},
            ]
        }
        result = validate_query_fields(q)
        assert result == {'_context.scan_id': '5'}
        recorded = console.export_text()
        assert "Field 'name' does not exist on type 'technology'" in recorded

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
        # All user fields invalid → fragment dropped entirely, returning {}
        from secator.rich import console
        console.export_text(clear=True)
        q = {'_type': 'technology', 'name': 'php', 'bogus': 'x'}
        result = validate_query_fields(q)
        assert result == {}
        recorded = console.export_text()
        assert "Field 'name' does not exist on type 'technology'" in recorded
        assert "Field 'bogus' does not exist on type 'technology'" in recorded

    def test_valid_url_status_code(self):
        q = {'_type': 'url', 'status_code': {'$ne': 200}}
        assert validate_query_fields(q) == q

    def test_valid_vulnerability_cvss_score(self):
        q = {'_type': 'vulnerability', 'cvss_score': {'$gt': 7}}
        assert validate_query_fields(q) == q

