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
        runner = _FakeRunner(
            config=config,
            workspace_name=workspace,
            errors=[],
            context={
                'workspace_id': workspace,
                'workspace_name': workspace,
                'drivers': drivers or [],
                'results': results,
            },
            reports_folder=Path(tempfile.mkdtemp()),
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
