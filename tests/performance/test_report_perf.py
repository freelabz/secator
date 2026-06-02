"""Performance tests for Report.build() and exporters with large result sets.

Run with:
    python -m pytest tests/performance/test_report_perf.py -s -v
"""
import tempfile
import time
import tracemalloc
import uuid
from contextlib import contextmanager
from pathlib import Path

from dotmap import DotMap

from secator.output_types.vulnerability import Vulnerability
from secator.report import Report


@contextmanager
def measure(label=''):
    """Context manager that measures wall time and peak memory (via tracemalloc)."""
    tracemalloc.start()
    t0 = time.perf_counter()
    result = {'elapsed': 0, 'peak_mb': 0}
    try:
        yield result
    finally:
        result['elapsed'] = time.perf_counter() - t0
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        result['peak_mb'] = peak / 1_048_576


def _make_runner(results, workspace='test_ws'):
    runner = DotMap()
    runner.config = DotMap({'name': 'perf_runner', 'type': 'task'})
    runner.workspace_name = workspace
    runner.errors = []
    runner.context = {
        'workspace_id': workspace,
        'workspace_name': workspace,
        'drivers': [],
        'results': results,
    }
    runner.reports_folder = Path(tempfile.mkdtemp())
    runner.toDict = lambda: {
        'name': 'perf_runner',
        'status': 'completed',
        'targets': [],
        'start_time': None,
        'end_time': None,
        'elapsed': None,
        'elapsed_human': None,
        'run_opts': {},
        'results_count': len(results),
    }
    return runner


def _build_report(results):
    """Helper: build a report from results and return (report, build_time)."""
    runner = _make_runner(results)
    report = Report(runner)
    t0 = time.perf_counter()
    report.build(query={})
    elapsed = time.perf_counter() - t0
    return report, elapsed


def _make_vuln_dicts(n):
    return [
        {
            '_type': 'vulnerability',
            'name': f'CVE-{i}',
            'matched_at': f'http://host{i}.com',
            'ip': f'10.0.{i // 256}.{i % 256}',
            'severity': ['low', 'medium', 'high', 'critical'][i % 4],
            'cvss_score': round((i % 100) / 10, 1),
        }
        for i in range(n)
    ]


def _make_vuln_objects(n):
    return [
        Vulnerability(
            name=f'CVE-{i}',
            matched_at=f'http://host{i}.com',
            ip=f'10.0.{i // 256}.{i % 256}',
            severity=['low', 'medium', 'high', 'critical'][i % 4],
            cvss_score=round((i % 100) / 10, 1),
        )
        for i in range(n)
    ]


class TestReportPerf:

    def test_build_10k_dicts(self):
        items = _make_vuln_dicts(10_000)
        runner = _make_runner(items)
        report = Report(runner)
        with measure() as m:
            report.build(query={})
        assert len(report.data['results']['vulnerability']) == 10_000
        print(f'\n  10k dicts:   {m["elapsed"]:.3f}s  {m["peak_mb"]:.1f} MB')
        assert m['elapsed'] < 5

    def test_build_10k_objects(self):
        items = _make_vuln_objects(10_000)
        runner = _make_runner(items)
        report = Report(runner)
        with measure() as m:
            report.build(query={})
        assert len(report.data['results']['vulnerability']) == 10_000
        print(f'\n  10k objects: {m["elapsed"]:.3f}s  {m["peak_mb"]:.1f} MB')
        assert m['elapsed'] < 5

    def test_build_100k_dicts(self):
        items = _make_vuln_dicts(100_000)
        runner = _make_runner(items)
        report = Report(runner)
        with measure() as m:
            report.build(query={})
        assert len(report.data['results']['vulnerability']) == 100_000
        print(f'\n  100k dicts:   {m["elapsed"]:.3f}s  {m["peak_mb"]:.1f} MB')
        assert m['elapsed'] < 30

    def test_build_100k_objects(self):
        items = _make_vuln_objects(100_000)
        runner = _make_runner(items)
        report = Report(runner)
        with measure() as m:
            report.build(query={})
        assert len(report.data['results']['vulnerability']) == 100_000
        print(f'\n  100k objects: {m["elapsed"]:.3f}s  {m["peak_mb"]:.1f} MB')
        assert m['elapsed'] < 30

    def test_build_1000k_dicts(self):
        items = _make_vuln_dicts(1_000_000)
        runner = _make_runner(items)
        report = Report(runner)
        with measure() as m:
            report.build(query={})
        assert len(report.data['results']['vulnerability']) == 1_000_000
        print(f'\n  1000k dicts:   {m["elapsed"]:.3f}s  {m["peak_mb"]:.1f} MB')
        assert m['elapsed'] < 60

    def test_build_1000k_objects(self):
        items = _make_vuln_objects(1_000_000)
        runner = _make_runner(items)
        report = Report(runner)
        with measure() as m:
            report.build(query={})
        assert len(report.data['results']['vulnerability']) == 1_000_000
        print(f'\n  1000k objects: {m["elapsed"]:.3f}s  {m["peak_mb"]:.1f} MB')
        assert m['elapsed'] < 60

    def test_build_10k_dicts_with_query(self):
        items = _make_vuln_dicts(10_000)
        runner = _make_runner(items)
        report = Report(runner)
        with measure() as m:
            report.build(query={'severity': 'critical'})
        assert len(report.data['results']['vulnerability']) == 2_500
        print(f'\n  10k dicts + filter:   {m["elapsed"]:.3f}s  {m["peak_mb"]:.1f} MB')
        assert m['elapsed'] < 5

    def test_build_10k_objects_with_query(self):
        items = _make_vuln_objects(10_000)
        runner = _make_runner(items)
        report = Report(runner)
        with measure() as m:
            report.build(query={'severity': 'critical'})
        assert len(report.data['results']['vulnerability']) == 2_500
        print(f'\n  10k objects + filter: {m["elapsed"]:.3f}s  {m["peak_mb"]:.1f} MB')
        assert m['elapsed'] < 5

    def test_build_10k_dicts_with_dedupe(self):
        # 5k unique + 5k duplicates
        base = _make_vuln_dicts(5_000)
        items = base + [d.copy() for d in base]
        runner = _make_runner(items)
        report = Report(runner)
        with measure() as m:
            report.build(query={}, dedupe=True)
        assert len(report.data['results']['vulnerability']) == 5_000
        print(f'\n  10k dicts + dedupe:   {m["elapsed"]:.3f}s  {m["peak_mb"]:.1f} MB')
        assert m['elapsed'] < 10

    def test_build_10k_objects_with_dedupe(self):
        base = _make_vuln_objects(5_000)
        items = base + list(base)  # same object refs = duplicates
        runner = _make_runner(items)
        report = Report(runner)
        with measure() as m:
            report.build(query={}, dedupe=True)
        assert len(report.data['results']['vulnerability']) == 5_000
        print(f'\n  10k objects + dedupe: {m["elapsed"]:.3f}s  {m["peak_mb"]:.1f} MB')
        assert m['elapsed'] < 10


class TestMarkDuplicatesPerf:
    """Simulate a live Runner calling mark_duplicates() after processing results."""

    def _make_live_runner(self, results):
        """Create a mock runner with the attributes mark_duplicates() needs."""
        runner = DotMap()
        runner.results = results
        runner.enable_duplicate_check = True
        runner.sync = True
        runner.id = None
        # Stub hooks and debug to no-ops
        runner.run_hooks = lambda *a, **kw: a[1] if len(a) > 1 else None
        runner.debug = lambda *a, **kw: None
        return runner

    def _make_unique_vulns(self, n):
        """Create n unique Vulnerability objects with unique UUIDs."""
        vulns = []
        for i in range(n):
            v = Vulnerability(
                name=f'CVE-{i}',
                matched_at=f'http://host{i}.com',
                ip=f'10.0.{i // 256}.{i % 256}',
                severity=['low', 'medium', 'high', 'critical'][i % 4],
                cvss_score=round((i % 100) / 10, 1),
            )
            v._uuid = str(uuid.uuid4())
            vulns.append(v)
        return vulns

    def _make_with_duplicates(self, unique_count, dupe_ratio=1.0):
        """Create unique_count unique vulns + dupe_ratio * unique_count duplicates."""
        base = self._make_unique_vulns(unique_count)
        dupe_count = int(unique_count * dupe_ratio)
        dupes = []
        for i in range(dupe_count):
            j = i % unique_count
            v = Vulnerability(
                name=f'CVE-{j}',
                matched_at=f'http://host{j}.com',
                ip=f'10.0.{j // 256}.{j % 256}',
                severity=['low', 'medium', 'high', 'critical'][j % 4],
                cvss_score=round((j % 100) / 10, 1),
            )
            v._uuid = str(uuid.uuid4())
            dupes.append(v)
        return base + dupes

    def _run_mark_duplicates(self, runner):
        """Call mark_duplicates bound to our mock runner."""
        from secator.runners._base import Runner
        Runner.mark_duplicates(runner)

    # --- No duplicates (best case) ---

    def test_mark_duplicates_10k_no_dupes(self):
        items = self._make_unique_vulns(10_000)
        runner = self._make_live_runner(items)
        with measure() as m:
            self._run_mark_duplicates(runner)
        marked = sum(1 for i in runner.results if i._duplicate)
        print(f'\n  mark_dupes 10k (0% dupes):     {m["elapsed"]:.3f}s  {m["peak_mb"]:.1f} MB  ({marked} marked)')
        assert marked == 0
        assert m['elapsed'] < 5

    def test_mark_duplicates_100k_no_dupes(self):
        items = self._make_unique_vulns(100_000)
        runner = self._make_live_runner(items)
        with measure() as m:
            self._run_mark_duplicates(runner)
        marked = sum(1 for i in runner.results if i._duplicate)
        print(f'\n  mark_dupes 100k (0% dupes):    {m["elapsed"]:.3f}s  {m["peak_mb"]:.1f} MB  ({marked} marked)')
        assert marked == 0
        assert m['elapsed'] < 30

    def test_mark_duplicates_1000k_no_dupes(self):
        items = self._make_unique_vulns(1_000_000)
        runner = self._make_live_runner(items)
        with measure() as m:
            self._run_mark_duplicates(runner)
        marked = sum(1 for i in runner.results if i._duplicate)
        print(f'\n  mark_dupes 1000k (0% dupes):   {m["elapsed"]:.3f}s  {m["peak_mb"]:.1f} MB  ({marked} marked)')
        assert marked == 0
        assert m['elapsed'] < 120

    # --- 50% duplicates ---

    def test_mark_duplicates_10k_50pct_dupes(self):
        items = self._make_with_duplicates(5_000, dupe_ratio=1.0)  # 5k unique + 5k dupes = 10k
        runner = self._make_live_runner(items)
        with measure() as m:
            self._run_mark_duplicates(runner)
        marked = sum(1 for i in runner.results if i._duplicate)
        print(f'\n  mark_dupes 10k (50% dupes):    {m["elapsed"]:.3f}s  {m["peak_mb"]:.1f} MB  ({marked} marked)')
        assert marked == 5_000
        assert m['elapsed'] < 5

    def test_mark_duplicates_100k_50pct_dupes(self):
        items = self._make_with_duplicates(50_000, dupe_ratio=1.0)
        runner = self._make_live_runner(items)
        with measure() as m:
            self._run_mark_duplicates(runner)
        marked = sum(1 for i in runner.results if i._duplicate)
        print(f'\n  mark_dupes 100k (50% dupes):   {m["elapsed"]:.3f}s  {m["peak_mb"]:.1f} MB  ({marked} marked)')
        assert marked == 50_000
        assert m['elapsed'] < 30

    def test_mark_duplicates_1000k_50pct_dupes(self):
        items = self._make_with_duplicates(500_000, dupe_ratio=1.0)
        runner = self._make_live_runner(items)
        with measure() as m:
            self._run_mark_duplicates(runner)
        marked = sum(1 for i in runner.results if i._duplicate)
        print(f'\n  mark_dupes 1000k (50% dupes):  {m["elapsed"]:.3f}s  {m["peak_mb"]:.1f} MB  ({marked} marked)')
        assert marked == 500_000
        assert m['elapsed'] < 120


class TestCelerySimulationPerf:
    """Simulate CeleryData polling behavior: each poll re-sends ALL accumulated results.

    Measures the cost of:
    1. iter_results UUID filtering (skipping already-yielded items)
    2. add_result UUID dedup (Runner layer)
    3. mark_duplicates after all results collected
    4. Report.build + export
    """

    def _make_vulns_with_uuids(self, n):
        """Create n unique Vulnerability objects with unique UUIDs."""
        vulns = []
        for i in range(n):
            v = Vulnerability(
                name=f'CVE-{i}',
                matched_at=f'http://host{i}.com',
                ip=f'10.0.{i // 256}.{i % 256}',
                severity=['low', 'medium', 'high', 'critical'][i % 4],
                cvss_score=round((i % 100) / 10, 1),
            )
            v._uuid = str(uuid.uuid4())
            vulns.append(v)
        return vulns

    def _simulate_celery_polls(self, all_items, num_polls, batch_size):
        """Simulate CeleryData.iter_results behavior: each poll sends ALL accumulated results.

        On each poll:
        - batch_size new items arrive (added to accumulated)
        - ALL accumulated items are iterated, but only new ones pass UUID filter

        Returns:
            tuple: (yielded_items, elapsed, poll_times)
        """
        yielded_uuids = set()
        yielded_items = []
        poll_times = []
        accumulated = []

        for poll in range(num_polls):
            # Simulate new batch arriving from remote worker
            start_idx = poll * batch_size
            end_idx = min(start_idx + batch_size, len(all_items))
            accumulated.extend(all_items[start_idx:end_idx])

            # Simulate iter_results: iterate ALL accumulated, skip already-yielded
            t0 = time.perf_counter()
            for item in accumulated:
                if item._uuid and item._uuid in yielded_uuids:
                    continue
                if item._uuid:
                    yielded_uuids.add(item._uuid)
                yielded_items.append(item)
            poll_times.append(time.perf_counter() - t0)

        return yielded_items, poll_times

    def _simulate_add_results(self, items):
        """Simulate Runner.add_result UUID dedup layer."""
        uuids = set()
        results = []
        t0 = time.perf_counter()
        for item in items:
            if item._uuid and item._uuid in uuids:
                continue
            uuids.add(item._uuid)
            results.append(item)
        elapsed = time.perf_counter() - t0
        return results, elapsed

    def _simulate_mark_duplicates(self, results):
        """Call real mark_duplicates on a mock runner."""
        from secator.runners._base import Runner
        runner = DotMap()
        runner.results = results
        runner.enable_duplicate_check = True
        runner.run_hooks = lambda *a, **kw: a[1] if len(a) > 1 else None
        runner.debug = lambda *a, **kw: None
        t0 = time.perf_counter()
        Runner.mark_duplicates(runner)
        elapsed = time.perf_counter() - t0
        return elapsed

    def _run_full_simulation(self, total_items, num_polls):
        """Run full CeleryData → add_result → mark_duplicates → Report pipeline."""
        batch_size = total_items // num_polls
        all_items = self._make_vulns_with_uuids(total_items)

        with measure() as m_total:
            # Phase 1: CeleryData polling (iter_results UUID filtering)
            yielded, poll_times = self._simulate_celery_polls(all_items, num_polls, batch_size)
            poll_total = sum(poll_times)

            # Phase 2: Runner.add_result UUID dedup
            results, add_time = self._simulate_add_results(yielded)

            # Phase 3: mark_duplicates
            mark_time = self._simulate_mark_duplicates(results)

            # Phase 4: Report.build
            runner = _make_runner(results)
            report = Report(runner)
            t0 = time.perf_counter()
            report.build(query={})
            build_time = time.perf_counter() - t0

        return {
            'total_items': total_items,
            'num_polls': num_polls,
            'batch_size': batch_size,
            'yielded': len(yielded),
            'results': len(results),
            'poll_total': poll_total,
            'poll_times': poll_times,
            'add_time': add_time,
            'mark_time': mark_time,
            'build_time': build_time,
            'peak_mb': m_total['peak_mb'],
        }

    def _print_results(self, r):
        total = r['poll_total'] + r['add_time'] + r['mark_time'] + r['build_time']
        print(f"\n  {r['total_items'] // 1000}k items, {r['num_polls']} polls (batch={r['batch_size']})")
        print(f"    iter_results (UUID filter): {r['poll_total']:.3f}s  "
              f"(last poll: {r['poll_times'][-1]:.3f}s over {r['total_items']} items)")
        print(f"    add_result (UUID dedup):    {r['add_time']:.3f}s")
        print(f"    mark_duplicates:            {r['mark_time']:.3f}s")
        print(f"    Report.build:               {r['build_time']:.3f}s")
        print(f"    TOTAL pipeline:             {total:.3f}s  {r['peak_mb']:.1f} MB peak")

    # --- 10k items ---

    def test_celery_sim_10k_10_polls(self):
        r = self._run_full_simulation(10_000, num_polls=10)
        self._print_results(r)
        assert r['yielded'] == 10_000
        assert r['poll_total'] + r['add_time'] + r['mark_time'] + r['build_time'] < 10

    def test_celery_sim_10k_50_polls(self):
        r = self._run_full_simulation(10_000, num_polls=50)
        self._print_results(r)
        assert r['yielded'] == 10_000
        assert r['poll_total'] + r['add_time'] + r['mark_time'] + r['build_time'] < 10

    # --- 100k items ---

    def test_celery_sim_100k_10_polls(self):
        r = self._run_full_simulation(100_000, num_polls=10)
        self._print_results(r)
        assert r['yielded'] == 100_000
        assert r['poll_total'] + r['add_time'] + r['mark_time'] + r['build_time'] < 30

    def test_celery_sim_100k_100_polls(self):
        r = self._run_full_simulation(100_000, num_polls=100)
        self._print_results(r)
        assert r['yielded'] == 100_000
        assert r['poll_total'] + r['add_time'] + r['mark_time'] + r['build_time'] < 60

    # --- 1000k items ---

    def test_celery_sim_1000k_10_polls(self):
        r = self._run_full_simulation(1_000_000, num_polls=10)
        self._print_results(r)
        assert r['yielded'] == 1_000_000
        assert r['poll_total'] + r['add_time'] + r['mark_time'] + r['build_time'] < 120

    def test_celery_sim_1000k_100_polls(self):
        r = self._run_full_simulation(1_000_000, num_polls=100)
        self._print_results(r)
        assert r['yielded'] == 1_000_000
        assert r['poll_total'] + r['add_time'] + r['mark_time'] + r['build_time'] < 300


class TestExporterPerf:

    # --- JSON exporter ---

    def _run_export_test(self, exporter_cls, make_fn, count, label, output_file):
        report, _ = _build_report(make_fn(count))
        with measure() as m:
            exporter_cls(report).send()
        out_path = Path(report.output_folder) / output_file
        size_mb = out_path.stat().st_size / 1_048_576
        print(f'\n  {label}  {m["elapsed"]:.3f}s  {m["peak_mb"]:.1f} MB peak  ({size_mb:.1f} MB on disk)')
        return m

    # --- JSON exporter ---

    def test_json_export_10k_dicts(self):
        from secator.exporters.json import JsonExporter
        m = self._run_export_test(JsonExporter, _make_vuln_dicts, 10_000, 'JSON 10k dicts:   ', 'report.json')
        assert m['elapsed'] < 5

    def test_json_export_10k_objects(self):
        from secator.exporters.json import JsonExporter
        m = self._run_export_test(JsonExporter, _make_vuln_objects, 10_000, 'JSON 10k objects: ', 'report.json')
        assert m['elapsed'] < 5

    def test_json_export_100k_dicts(self):
        from secator.exporters.json import JsonExporter
        m = self._run_export_test(JsonExporter, _make_vuln_dicts, 100_000, 'JSON 100k dicts:  ', 'report.json')
        assert m['elapsed'] < 30

    def test_json_export_100k_objects(self):
        from secator.exporters.json import JsonExporter
        m = self._run_export_test(JsonExporter, _make_vuln_objects, 100_000, 'JSON 100k objects:', 'report.json')
        assert m['elapsed'] < 30

    def test_json_export_1000k_dicts(self):
        from secator.exporters.json import JsonExporter
        m = self._run_export_test(JsonExporter, _make_vuln_dicts, 1_000_000, 'JSON 1000k dicts:  ', 'report.json')
        assert m['elapsed'] < 120

    def test_json_export_1000k_objects(self):
        from secator.exporters.json import JsonExporter
        m = self._run_export_test(JsonExporter, _make_vuln_objects, 1_000_000, 'JSON 1000k objects:', 'report.json')
        assert m['elapsed'] < 120

    # --- CSV exporter ---

    def test_csv_export_10k_dicts(self):
        from secator.exporters.csv import CsvExporter
        m = self._run_export_test(CsvExporter, _make_vuln_dicts, 10_000, 'CSV 10k dicts:   ', 'report_vulnerability.csv')
        assert m['elapsed'] < 5

    def test_csv_export_10k_objects(self):
        from secator.exporters.csv import CsvExporter
        m = self._run_export_test(CsvExporter, _make_vuln_objects, 10_000, 'CSV 10k objects: ', 'report_vulnerability.csv')
        assert m['elapsed'] < 5

    def test_csv_export_100k_dicts(self):
        from secator.exporters.csv import CsvExporter
        m = self._run_export_test(CsvExporter, _make_vuln_dicts, 100_000, 'CSV 100k dicts:  ', 'report_vulnerability.csv')
        assert m['elapsed'] < 30

    def test_csv_export_100k_objects(self):
        from secator.exporters.csv import CsvExporter
        m = self._run_export_test(CsvExporter, _make_vuln_objects, 100_000, 'CSV 100k objects:', 'report_vulnerability.csv')
        assert m['elapsed'] < 30

    def test_csv_export_1000k_dicts(self):
        from secator.exporters.csv import CsvExporter
        m = self._run_export_test(CsvExporter, _make_vuln_dicts, 1_000_000, 'CSV 1000k dicts:  ', 'report_vulnerability.csv')
        assert m['elapsed'] < 120

    def test_csv_export_1000k_objects(self):
        from secator.exporters.csv import CsvExporter
        m = self._run_export_test(CsvExporter, _make_vuln_objects, 1_000_000, 'CSV 1000k objects:', 'report_vulnerability.csv')
        assert m['elapsed'] < 120

    # --- TXT exporter ---

    def test_txt_export_10k_dicts(self):
        from secator.exporters.txt import TxtExporter
        m = self._run_export_test(TxtExporter, _make_vuln_dicts, 10_000, 'TXT 10k dicts:   ', 'report_vulnerability.txt')
        assert m['elapsed'] < 5

    def test_txt_export_10k_objects(self):
        from secator.exporters.txt import TxtExporter
        m = self._run_export_test(TxtExporter, _make_vuln_objects, 10_000, 'TXT 10k objects: ', 'report_vulnerability.txt')
        assert m['elapsed'] < 5

    def test_txt_export_100k_dicts(self):
        from secator.exporters.txt import TxtExporter
        m = self._run_export_test(TxtExporter, _make_vuln_dicts, 100_000, 'TXT 100k dicts:  ', 'report_vulnerability.txt')
        assert m['elapsed'] < 30

    def test_txt_export_100k_objects(self):
        from secator.exporters.txt import TxtExporter
        m = self._run_export_test(TxtExporter, _make_vuln_objects, 100_000, 'TXT 100k objects:', 'report_vulnerability.txt')
        assert m['elapsed'] < 30

    def test_txt_export_1000k_dicts(self):
        from secator.exporters.txt import TxtExporter
        m = self._run_export_test(TxtExporter, _make_vuln_dicts, 1_000_000, 'TXT 1000k dicts:  ', 'report_vulnerability.txt')
        assert m['elapsed'] < 120

    def test_txt_export_1000k_objects(self):
        from secator.exporters.txt import TxtExporter
        m = self._run_export_test(TxtExporter, _make_vuln_objects, 1_000_000, 'TXT 1000k objects:', 'report_vulnerability.txt')
        assert m['elapsed'] < 120
