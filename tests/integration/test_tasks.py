import os
import shutil
import unittest
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from time import sleep, time

from secator.loader import discover_tasks
from secator.rich import console
from secator.runners import Command
from secator.utils import merge_opts
from secator.utils_test import (META_OPTS, TEST_TASKS, CommandOutputTester,
							  load_fixture)
from tests.integration.inputs import INPUTS_TASKS
from tests.integration.outputs import OUTPUTS_TASKS, OUTPUTS_CHECKS

INTEGRATION_DIR = os.path.dirname(os.path.abspath(__file__))
NO_CLEANUP = bool(os.environ.get('TEST_NO_CLEANUP', '0'))
# Each task runs a real tool against the (shared) lab targets, so it's I/O/network-bound:
# run them concurrently in one process (the lab is set up once in setUp; no per-task Docker
# churn and coverage stays intact — unlike pytest-xdist which would re-run setUp per worker).
TASK_WORKERS = int(os.environ.get('SECATOR_TEST_TASK_WORKERS', '8'))


class TestTasks(unittest.TestCase, CommandOutputTester):
	def setUp(self):
		warnings.simplefilter('ignore', category=ResourceWarning)
		warnings.simplefilter('ignore', category=DeprecationWarning)
		Command.execute(
			f'sh {INTEGRATION_DIR}/setup.sh',
			quiet=False,
			cwd=INTEGRATION_DIR
		)
		sleep(5)

	def tearDown(self):
		Command.execute(
			f'sh {INTEGRATION_DIR}/teardown.sh',
			quiet=False,
			cwd=INTEGRATION_DIR
		)

	def test_tasks(self):
		opts = META_OPTS.copy()
		extra_opts = {
			'dirsearch.filter_size': 1987,
			'dnsx.wordlist': load_fixture('wordlist_dns', INTEGRATION_DIR, only_path=True),
			'ffuf.filter_size': 1987,
			'feroxbuster.filter_size': 1987,
			'arjun.wordlist': False,
			'h8mail.local_breach': load_fixture('h8mail_breach', INTEGRATION_DIR, only_path=True),
			'nmap.port': '3000,8080',
			'nmap.tcp_connect': True,
			'nmap.version_detection': True,
			'nmap.skip_host_discovery': True,
			# gau queries several public URL archives; the slow ones (commoncrawl/otx/urlscan)
			# dominate its runtime and add flakiness. Restrict it to the wayback archive — reliably
			# non-empty for this target and ~2x faster (gau ~72s -> ~34s). We no longer assert a
			# specific archived URL (see outputs.py), so a single reliable source is all we need.
			'gau.providers': 'wayback',
			'match_codes': '200',
			'maigret.site': 'github',
			'trivy.mode': 'repo',
			# trufflehog verifies every detected secret via live provider network calls by
			# default, which is slow and network-flaky in CI (observed up to ~46 min). We only
			# assert detection of a seeded private key (an offline detector match), so skip
			# verification to keep the run fast and deterministic.
			'trufflehog.no_verification': True,
			'testssl.server_defaults': True,
			'wordlist': load_fixture('wordlist', INTEGRATION_DIR, only_path=True),
			# PR #1512 service tasks (targets wired in inputs.py, services in docker-compose.yml).
			# nxc needs a real connection timeout (META_OPTS' global TIMEOUT=1 is far too short for
			# the SMB/FTP handshake + enumeration, which makes nxc exit before producing output).
			'nxc_smb.shares': True,
			'nxc_smb.timeout': 30,
			'nxc_ftp.username': 'testuser',
			'nxc_ftp.password': 'testpass',
			'nxc_ftp.timeout': 30,
			# The registry lab maps host 15000 -> container 5000, so pass the registry port
			# explicitly via docker_port.
			'dockerregistrygrabber.docker_port': 15000,
			# droopescan.mode defaults to 'drupal', matching the Drupal 7 lab container.
			# Zabbix agent has remote commands enabled in the lab → exercise the RCE detection path.
			'zabbix_get.key': 'system.run[id]',
		}
		# TODO: copy profile and test with profile
		# opts['profiles'] = ['all']

		# Merge opts
		opts = merge_opts(opts, extra_opts)

		# Remove unit tests options
		del opts['nmap.output_path']
		del opts['dirsearch.output_path']
		del opts['gitleaks_output_path']
		del opts['maigret.output_path']
		del opts['wpscan.output_path']
		del opts['h8mail.output_path']
		del opts['wpprobe.output_path']
		del opts['arjun.output_path']
		del opts['trivy.output_path']
		del opts['wafw00f.output_path']
		del opts['testssl.output_path']
		del opts['timeout']

		tasks = discover_tasks()
		test_tasks_names = [t.name for t in TEST_TASKS]
		TASKS = [t for t in tasks if t.__name__ in test_tasks_names]

		durations = {}

		def run_one(cls):
			"""Run and assert ONE task. Returns an error string on failure, None on pass/skip."""
			name = cls.__name__
			if name == 'msfconsole':  # skip msfconsole test as it's stuck
				return None
			input = INPUTS_TASKS.get(name)
			if input is None and len(cls.input_types) > 0:
				input = INPUTS_TASKS.get(cls.input_types[0], [])
			if not input:
				console.print(f'\tTesting task {name} ... [dim gold3] skipped (no input)[/]')
				return None
			# Skip (don't fail) when the tool's binary isn't installed: some tools can't be
			# installed in a vanilla CI image on every platform (e.g. a libtins C++ build, a
			# runtime kernel module, root/Windows-only tooling). A missing binary is an
			# environment gap, not a regression — mirror the "skipped (no input)" path. Tools
			# that DID install still run and assert, so installable coverage is preserved.
			bin_name = (cls.cmd or '').split()[0] if getattr(cls, 'cmd', None) else None
			if bin_name and shutil.which(bin_name) is None:
				console.print(f'\tTesting task {name} ... [dim gold3] skipped (binary {bin_name!r} not installed)[/]')
				return None
			# Skip (don't fail) a tool that needs root when we're not root: the CI runner is
			# unprivileged, so a raw-socket/privileged tool (e.g. masscan) can't run and would
			# only ever error with a non-zero return code. This is an environment constraint,
			# not a regression — same rationale as the missing-binary skip above.
			is_root = hasattr(os, 'geteuid') and os.geteuid() == 0
			if getattr(cls, 'requires_sudo', False) and not is_root:
				console.print(f'\tTesting task {name} ... [dim gold3] skipped (requires root, running unprivileged)[/]')
				return None
			outputs = OUTPUTS_TASKS.get(name, [])
			# Fresh opts per task: runners mutate their run_opts, so sharing one dict across
			# concurrent runs would race.
			task = cls(input, **dict(opts))
			started = time()
			try:
				self._test_runner_output(
					task,
					expected_output_types=cls.output_types,
					expected_results=outputs,
					empty_results_allowed=False,
					additional_checks=OUTPUTS_CHECKS
				)
				return None
			except AssertionError as e:
				return f'ERROR ({name}): {e}'
			finally:
				durations[name] = time() - started

		# Run the tasks concurrently (I/O-bound). Collect failures and fail once at the end so
		# every task is still exercised on a run, like the original sequential subTest loop.
		failures = []
		with ThreadPoolExecutor(max_workers=TASK_WORKERS) as executor:
			futures = {executor.submit(run_one, cls): cls for cls in TASKS}
			for future in as_completed(futures):
				err = future.result()
				if err:
					failures.append(err)

		# Per-task duration recap (slowest first) — surfaces which tool runs to narrow/parallelize.
		if durations:
			console.print('\n[bold]Per-task durations (slowest first):[/]')
			for name, dur in sorted(durations.items(), key=lambda kv: kv[1], reverse=True):
				console.print(f'  {dur:6.1f}s  {name}')

		if failures:
			raise AssertionError("\n\n" + "\n\n".join(failures))
