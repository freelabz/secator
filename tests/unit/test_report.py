import tempfile
from pathlib import Path
from dotmap import DotMap
from secator.report import Report


class TestReportBuild:

    def _make_runner(self, results, workspace='test_ws', drivers=None):
        runner = DotMap()
        runner.config = DotMap({'name': 'test_runner', 'type': 'task'})
        runner.workspace_name = workspace
        runner.errors = []
        runner.context = {
            'workspace_id': workspace,
            'workspace_name': workspace,
            'drivers': drivers or [],
            'results': results,
        }
        runner.reports_folder = Path(tempfile.mkdtemp())
        runner.toDict = lambda: {
            'name': 'test_runner',
            'status': 'completed',
            'targets': [],
            'start_time': None,
            'end_time': None,
            'elapsed': None,
            'elapsed_human': None,
            'run_opts': {},
            'results_count': 0,
        }
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
