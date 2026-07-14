import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
from secator.report import Report


class _FakeRunner(SimpleNamespace):
    """Test stub whose toDict() can actually be overridden.

    DotMap silently stores `toDict` as a dict key instead of overriding the
    built-in method, which masked missing fields in Report.build() output.
    """
    def toDict(self):
        return self._to_dict


class TestReportBuild:

    def _make_runner(self, results, workspace='test_ws', drivers=None):
        config = SimpleNamespace(name='test_runner', type='task')
        # Store-only model: findings live in the run's report.json, not in memory.
        reports_folder = Path(tempfile.mkdtemp())
        grouped = {}
        for r in results:
            grouped.setdefault(r['_type'], []).append(r)
        with open(reports_folder / 'report.json', 'w') as f:
            json.dump({'info': {'name': 'test_runner'}, 'results': grouped}, f)
        runner = _FakeRunner(
            config=config,
            workspace_name=workspace,
            errors=[],
            context={
                'workspace_id': workspace,
                'workspace_name': workspace,
                'drivers': drivers or [],
            },
            reports_folder=reports_folder,
            results=results,
            _to_dict={
                'name': 'test_runner',
                'status': 'completed',
                'targets': [],
                'start_time': None,
                'end_time': None,
                'elapsed': None,
                'elapsed_human': None,
                'run_opts': {'profiles': ['aggressive']},
                'results_count': 0,
            },
        )
        return runner

    def test_build_filters_by_type(self):
        vuln = {'_type': 'vulnerability', 'name': 'CVE-1', 'severity': 'high', 'cvss_score': 9.0}
        domain = {'_type': 'domain', 'name': 'example.com'}
        runner = self._make_runner([vuln, domain])
        report = Report(runner)
        report.build(query={'_type': 'vulnerability'})
        assert len(report.data['results'].get('vulnerability', [])) == 1
        assert report.data['results'].get('domain', []) == []

    def test_build_with_empty_query_returns_all_types(self):
        vuln = {'_type': 'vulnerability', 'name': 'CVE-1', 'cvss_score': 9.0}
        domain = {'_type': 'domain', 'name': 'example.com'}
        runner = self._make_runner([vuln, domain])
        report = Report(runner)
        report.build(query={})
        assert len(report.data['results'].get('vulnerability', [])) == 1
        assert len(report.data['results'].get('domain', [])) == 1

    def test_build_dedupe_removes_duplicates(self):
        vuln = {'_type': 'vulnerability', 'name': 'CVE-1', 'cvss_score': 9.0, 'matched_at': 'http://x.com', 'ip': '1.2.3.4'}
        runner = self._make_runner([vuln, vuln.copy()])
        report = Report(runner)
        report.build(query={}, dedupe=True)
        assert len(report.data['results'].get('vulnerability', [])) == 1

    def test_build_returns_more_than_default_limit(self):
        """Report.build() should not be limited to the QueryEngine default of 100."""
        vulns = [
            {'_type': 'vulnerability', 'name': f'CVE-{i}', 'cvss_score': 5.0, 'matched_at': f'http://host{i}.com', 'ip': '1.2.3.4'}
            for i in range(150)
        ]
        runner = self._make_runner(vulns)
        report = Report(runner)
        report.build(query={})
        assert len(report.data['results'].get('vulnerability', [])) == 150

    def test_build_persists_profiles_in_run_opts(self):
        runner = self._make_runner([])
        report = Report(runner)
        report.build(query={})
        assert report.data['info']['run_opts']['profiles'] == ['aggressive']

    def test_build_no_preloaded_results_does_not_short_circuit_backend(self):
        """When runner has no pre-loaded results, Report.build() must not pass empty list to context.

        An empty list in context['results'] causes JsonBackend._load_all_findings() to return []
        immediately (since [] is not None), bypassing the filesystem scan entirely.
        """
        runner = self._make_runner([])  # empty results list
        # Remove 'results' from context to simulate a runner with no pre-loaded results
        # (mirrors what report_show does when building runner without runner.results)
        if 'results' in runner.context:
            del runner.context['results']
        report = Report(runner)
        # Should not crash and data structure must be valid
        report.build(query={})
        assert 'results' in report.data
        assert 'info' in report.data


class TestReportBuildFromStore:
	"""Step 4: with the inter-task payload dropped, tasks return topology-only, so the
	final report must assemble from the STORE (the live report.json files), not from the
	runner's in-memory results. Same query path for sync and async."""

	def _write_store(self, reports_dir, ws, findings):
		# JsonBackend reads <reports_dir>/<ws>/tasks/<id>/report.json
		task_dir = Path(reports_dir) / ws / 'tasks' / 'task_abc'
		task_dir.mkdir(parents=True, exist_ok=True)
		results = {}
		for f in findings:
			f.setdefault('_context', {'workspace_id': ws})
			results.setdefault(f['_type'], []).append(f)
		(task_dir / 'report.json').write_text(json.dumps({'info': {}, 'results': results}))

	def _runner(self, reports_dir, ws, in_memory_results):
		config = SimpleNamespace(name='test_runner', type='workflow')
		return _FakeRunner(
			config=config, workspace_name=ws, errors=[],
			context={'workspace_id': ws, 'workspace_name': ws, 'drivers': ['json']},
			reports_folder=Path(reports_dir) / ws, results=in_memory_results,
			_to_dict={'name': 'test_runner', 'status': 'completed', 'targets': [],
					  'start_time': None, 'end_time': None, 'elapsed': None,
					  'elapsed_human': None, 'run_opts': {}, 'results_count': 0},
		)

	def test_report_assembles_findings_from_store_with_topology_only_results(self, monkeypatch):
		from secator.config import CONFIG
		reports_dir = tempfile.mkdtemp()
		monkeypatch.setattr(CONFIG.dirs, 'reports', Path(reports_dir))
		ws = 'store_ws'
		self._write_store(reports_dir, ws, [
			{'_type': 'url', 'url': 'http://x/a'},
			{'_type': 'url', 'url': 'http://x/b'},
			{'_type': 'vulnerability', 'name': 'CVE-1', 'cvss_score': 9.0},
		])
		# The runner carries a TOPOLOGY-ONLY payload (a Target + Info, no findings).
		topo = [
			{'_type': 'target', 'name': 'http://x'},
			{'_type': 'info', 'message': 'Task created'},
		]
		runner = self._runner(reports_dir, ws, topo)
		report = Report(runner)
		report.build(query={})
		urls = sorted(u.get('url') if isinstance(u, dict) else u.url for u in report.data['results']['url'])
		assert urls == ['http://x/a', 'http://x/b']
		assert len(report.data['results']['vulnerability']) == 1


class TestJsonlExporter:
    """Tests for the JsonlExporter."""

    def _make_report(self, results):
        config = SimpleNamespace(name='test_runner', type='task')
        # Store-only model: findings live in the run's report.json, not in memory.
        reports_folder = Path(tempfile.mkdtemp())
        grouped = {}
        for r in results:
            grouped.setdefault(r['_type'], []).append(r)
        with open(reports_folder / 'report.json', 'w') as f:
            json.dump({'info': {'name': 'test_runner'}, 'results': grouped}, f)
        runner = SimpleNamespace(
            config=config,
            workspace_name='test_ws',
            errors=[],
            context={'workspace_id': 'test_ws', 'workspace_name': 'test_ws'},
            reports_folder=reports_folder,
        )
        runner.toDict = lambda: {
            'name': 'test_runner', 'status': 'completed', 'targets': [],
            'start_time': None, 'end_time': None, 'elapsed': None,
            'elapsed_human': None, 'run_opts': {}, 'results_count': 0,
        }
        report = Report(runner)
        report.build(query={})
        return report

    def test_jsonl_outputs_one_line_per_result(self, capsys):
        from secator.exporters.jsonl import JsonlExporter
        vuln = {'_type': 'vulnerability', 'name': 'CVE-1', 'cvss_score': 9.0}
        domain = {'_type': 'domain', 'name': 'example.com'}
        report = self._make_report([vuln, domain])
        JsonlExporter(report).send()
        captured = capsys.readouterr()
        lines = [ln for ln in captured.out.strip().splitlines() if ln]
        assert len(lines) == 2
        for line in lines:
            obj = json.loads(line)
            assert '_type' in obj

    def test_jsonl_each_line_is_valid_json(self, capsys):
        from secator.exporters.jsonl import JsonlExporter
        vuln = {'_type': 'vulnerability', 'name': 'test-vuln', 'cvss_score': 7.5}
        report = self._make_report([vuln])
        JsonlExporter(report).send()
        captured = capsys.readouterr()
        lines = [ln for ln in captured.out.strip().splitlines() if ln]
        assert len(lines) == 1
        obj = json.loads(lines[0])
        assert obj.get('_type') == 'vulnerability'
        assert obj.get('name') == 'test-vuln'

    def test_jsonl_empty_results_produces_no_output(self, capsys):
        from secator.exporters.jsonl import JsonlExporter
        report = self._make_report([])
        JsonlExporter(report).send()
        captured = capsys.readouterr()
        assert captured.out.strip() == ''

    def test_jsonl_writes_to_stdout_not_file(self, capsys):
        from secator.exporters.jsonl import JsonlExporter
        vuln = {'_type': 'vulnerability', 'name': 'x', 'cvss_score': 5.0}
        report = self._make_report([vuln])
        JsonlExporter(report).send()
        captured = capsys.readouterr()
        assert captured.out.strip() != ''
        # No new files should be created in the output folder
        assert not list(report.output_folder.glob('*.jsonl'))
