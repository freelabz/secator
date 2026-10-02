"""Rough duration estimation for runners, from run options.

Pure functions, no I/O and no network: given a task/workflow/scan definition, a
``run_opts`` dict and a target count, return an order-of-magnitude
``Estimate``. The point is a "seconds / minutes / hours / this-will-eat-your-
budget" signal, not a promise.

Two ingredients:

- an **options-aware algorithm** (``task_work_units`` + the per-task model
  table below) that reacts to ports / wordlist / rate / depth / threads — the
  only thing sensitive to the choices a user is about to make;
- an optional **calibration** mapping (``{task: {"p50", "p90", "n"}}`` in
  observed seconds-per-target) supplied by the caller. When present it anchors
  the common case; the algorithm captures the deviation. See ``blend``.

This module ships no calibration data of its own — callers pass their own
observations in. With no calibration it degrades to pure algorithmic estimates.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

# Cap how much we trust observed averages: they are options-blind, so even with
# a lot of samples the algorithm keeps a 30% say so a divergent option choice
# (all-ports at rate 1) can still pull the estimate up.
OBSERVED_TRUST_CAP = 0.7
OBSERVED_TRUST_SAMPLES = 30  # samples at which trust reaches the cap

# Worker-fleet concurrency ceiling for chunked tasks (order-of-magnitude knob,
# not a scheduler simulation).
DEFAULT_MAX_PARALLEL = 20

# Fixed per-task startup cost (process spawn, template/wordlist load, DNS).
DEFAULT_SETUP_S = 5.0

# Fallback effective request/packet rate when a task is rate-capable but no
# rate_limit is set (tool runs "as fast as it can"). Per-task overrides below.
DEFAULT_RATE = 1000.0

# Default per-target concurrency (threads). Matches the observed fleet median.
DEFAULT_THREADS = 50.0


@dataclass
class Estimate:
	seconds: float          # point estimate (p50-ish)
	low: float              # optimistic (~p25)
	high: float             # pessimistic (~p90), the budget-warning number
	basis: str              # "observed" | "algorithmic" | "blended" | "empty"

	def human(self) -> str:
		return _human(self.seconds)

	def to_dict(self) -> dict:
		return {
			'seconds': round(self.seconds, 1),
			'low': round(self.low, 1),
			'high': round(self.high, 1),
			'basis': self.basis,
			'human': self.human(),
			'human_high': _human(self.high),
		}


def _human(s: float) -> str:
	if s < 1:
		return '<1s'
	if s < 90:
		return f'~{int(round(s))}s'
	if s < 90 * 60:
		return f'~{int(round(s / 60))} min'
	if s < 48 * 3600:
		return f'~{s / 3600:.1f} h'.replace('.0 h', ' h')
	return f'~{int(round(s / 86400))} d'


# ---------------------------------------------------------------------------
# Per-task work model
# ---------------------------------------------------------------------------

# How one target's work scales, and how a task parallelises. Only the tasks
# worth modelling are listed; anything else falls back to pure observed
# calibration (or a flat default).
#
#   chunk : input_chunk_size — 1 = one task per target, -1 = no split (all
#           targets in one task), N = N targets per task.
#   rate_bound : True if work/rate dominates (requests/packets/probes per sec).
#   conc  : whether per-target work is divided by thread concurrency.
#   rate  : default effective rate when no rate_limit is set.
#   setup : fixed per-task cost.
TASK_MODELS: dict[str, dict] = {
	'nmap':        {'chunk': 1,  'rate_bound': True,  'conc': False, 'rate': 1000.0, 'setup': 8.0},
	'naabu':       {'chunk': 1,  'rate_bound': True,  'conc': False, 'rate': 1000.0, 'setup': 5.0},
	'nuclei':      {'chunk': 20, 'rate_bound': True,  'conc': True,  'rate': 150.0,  'setup': 10.0},
	'ffuf':        {'chunk': 1,  'rate_bound': True,  'conc': True,  'rate': 100.0,  'setup': 5.0},
	'feroxbuster': {'chunk': 1,  'rate_bound': True,  'conc': True,  'rate': 100.0,  'setup': 5.0},
	'dalfox':      {'chunk': 20, 'rate_bound': False, 'conc': True,  'rate': 100.0,  'setup': 5.0},
	'dnsx':        {'chunk': -1, 'rate_bound': True,  'conc': True,  'rate': 1000.0, 'setup': 3.0},
	'katana':      {'chunk': 1,  'rate_bound': True,  'conc': True,  'rate': 100.0,  'setup': 5.0},
	'gospider':    {'chunk': 1,  'rate_bound': True,  'conc': True,  'rate': 100.0,  'setup': 5.0},
	'arjun':       {'chunk': 20, 'rate_bound': False, 'conc': True,  'rate': 100.0,  'setup': 5.0},
	'httpx':       {'chunk': -1, 'rate_bound': True,  'conc': True,  'rate': 1000.0, 'setup': 3.0},
	# Fixed test batteries: no formula drives them — work is ~constant/target.
	'testssl':     {'chunk': 1,  'rate_bound': False, 'conc': False, 'fixed': 190.0, 'setup': 5.0},
	'trufflehog':  {'chunk': -1, 'rate_bound': False, 'conc': False, 'fixed': 15.0,  'setup': 5.0},
	'gitleaks':    {'chunk': -1, 'rate_bound': False, 'conc': False, 'fixed': 15.0,  'setup': 5.0},
	'wpscan':      {'chunk': 1,  'rate_bound': False, 'conc': False, 'fixed': 60.0,  'setup': 5.0},
}

# -sV / -A roughly multiply nmap's per-port cost (version probes).
NMAP_SV_MULT = 2.5
NMAP_DEFAULT_PORTS = 1000   # nmap default is its top-1000
NMAP_ALL_PORTS = 65535
NAABU_DEFAULT_PORTS = 100   # naabu default top-100

# Rough default wordlist sizes (lines) for fuzz/brute tasks.
DEFAULT_WORDLIST_LEN = 5000


def _num(v, default=None):
	try:
		if v is None:
			return default
		return float(v)
	except (TypeError, ValueError):
		return default


def _port_count(opts: dict, default: int) -> int:
	ports = opts.get('ports')
	if ports:
		if str(ports).strip() == '-':
			return NMAP_ALL_PORTS
		# "22,80,443" or "1-1024"
		total = 0
		for part in str(ports).split(','):
			part = part.strip()
			if '-' in part:
				try:
					lo, hi = part.split('-', 1)
					total += max(0, int(hi) - int(lo) + 1)
				except ValueError:
					total += 1
			elif part:
				total += 1
		return total or default
	top = opts.get('top_ports')
	if top:
		try:
			return int(top)
		except (TypeError, ValueError):
			return default
	return default


def task_work_units(task_name: str, opts: dict) -> float | None:
	"""Work-units one target costs for ``task_name`` given ``opts``.

	Returns ``None`` when the task has no options-driven work model (fast or
	fixed-battery tasks) — the caller then leans on observed calibration.
	"""
	base = task_name.split('/')[0]  # "nmap/light" -> "nmap"
	model = TASK_MODELS.get(base)
	if not model or 'fixed' in model:
		return None
	opts = opts or {}
	if base == 'nmap':
		mult = NMAP_SV_MULT if (opts.get('version_detection') or opts.get('detect_all')) else 1.0
		return _port_count(opts, NMAP_DEFAULT_PORTS) * mult
	if base == 'naabu':
		return _port_count(opts, NAABU_DEFAULT_PORTS)
	if base in ('ffuf', 'feroxbuster', 'arjun', 'dnsx'):
		w = _num(opts.get('wordlist_size'), DEFAULT_WORDLIST_LEN)
		if base == 'feroxbuster':
			w *= max(1, int(_num(opts.get('depth'), 1)))
		return w
	if base in ('katana', 'gospider'):
		depth = max(1, int(_num(opts.get('depth'), 2)))
		return float(15 ** depth)  # pages ~ branching^depth, b~15
	if base == 'nuclei':
		# template count, cut by severity/tag filters (rough)
		tmpl = _num(opts.get('template_count'), 3000)
		if opts.get('severity') or opts.get('tags') or opts.get('templates'):
			tmpl *= 0.2
		return tmpl
	if base == 'dalfox':
		params = _num(opts.get('param_count'), 10)
		return params * 30  # ~30 XSS payloads/param
	return None


def _effective_rate(opts: dict, model: dict) -> float:
	r = _num(opts.get('rate_limit'))
	if r and r > 0:
		return r
	return model.get('rate', DEFAULT_RATE)


def _concurrency(opts: dict, model: dict) -> float:
	if not model.get('conc'):
		return 1.0
	c = _num(opts.get('threads'), DEFAULT_THREADS)
	return max(1.0, c)


def _task_body(task_name: str, opts: dict, n_chunk_targets: int, model: dict) -> float:
	"""Seconds for one chunk of ``n_chunk_targets`` targets (excl. setup)."""
	opts = opts or {}
	if 'fixed' in model:
		return model['fixed'] * max(1, n_chunk_targets)
	units = task_work_units(task_name, opts)
	if units is None:
		return model.get('fixed', 1.0) * max(1, n_chunk_targets)
	work = units * n_chunk_targets * (1.0 + _num(opts.get('retries'), 0.0))
	t_rate = work / _effective_rate(opts, model) if model.get('rate_bound') else 0.0
	t_conc = work / _concurrency(opts, model) if model.get('conc') else 0.0
	t_delay = _num(opts.get('delay'), 0.0) * work
	body = max(t_rate, t_conc)
	if body == 0.0:  # neither rate- nor concurrency-bound: units ~ seconds
		body = work
	return body + t_delay


def _chunks(n_targets: int, chunk: int) -> tuple[int, int]:
	"""(#chunks, targets-per-chunk) for a chunk size (``-1`` = no split)."""
	n_targets = max(1, n_targets)
	if chunk == -1 or chunk >= n_targets:
		return 1, n_targets
	if chunk <= 0:
		chunk = 1
	return math.ceil(n_targets / chunk), chunk


def estimate_task(task_name: str, opts: dict, n_targets: int,
				  calibration: dict | None = None,
				  max_parallel: int = DEFAULT_MAX_PARALLEL) -> Estimate:
	"""Algorithmic estimate for one task over ``n_targets``, blended with the
	observed calibration (seconds/target) when available."""
	n_targets = max(1, int(n_targets or 1))
	base = task_name.split('/')[0]
	model = TASK_MODELS.get(base)
	calib = _lookup_calibration(task_name, calibration)

	# Algorithmic estimate.
	t_algo = None
	if model:
		setup = model.get('setup', DEFAULT_SETUP_S)
		n_chunks, per_chunk_targets = _chunks(n_targets, model.get('chunk', 1))
		waves = math.ceil(n_chunks / max(1, max_parallel))
		per_chunk = setup + _task_body(task_name, opts, per_chunk_targets, model)
		t_algo = waves * per_chunk

	# Observed estimate (options-blind, flat per target).
	t_obs = calib['p50'] * n_targets if calib else None
	return _combine(t_algo, t_obs, calib)


def estimate_workflow(wf_cfg: dict, opts: dict, n_targets: int,
					  calibration: dict | None = None,
					  max_parallel: int = DEFAULT_MAX_PARALLEL) -> Estimate:
	"""Compose task estimates. A ``_``-prefixed key is a parallel group (its
	members run concurrently → ``max``); everything else chains → ``sum``."""
	tasks = (wf_cfg or {}).get('tasks') or {}
	parts = _walk_tasks(tasks, opts, n_targets, calibration, max_parallel)
	return _sum_estimates(parts)


def estimate_scan(scan_cfg: dict, opts: dict, n_targets: int,
				  calibration: dict | None = None,
				  registry: dict | None = None,
				  max_parallel: int = DEFAULT_MAX_PARALLEL) -> Estimate:
	"""Sum of referenced workflows (scans run their workflows sequentially).

	``registry`` maps a workflow name to its config dict so the scan's workflow
	references can be expanded; names missing from it are skipped.
	"""
	workflows = (scan_cfg or {}).get('workflows') or {}
	registry = registry or {}
	parts = []
	for name in workflows:
		wf_cfg = registry.get(name)
		if wf_cfg:
			parts.append(estimate_workflow(wf_cfg, opts, n_targets, calibration, max_parallel))
	return _sum_estimates(parts)


def estimate(cfg: dict, opts: dict, n_targets: int,
			 calibration: dict | None = None,
			 registry: dict | None = None,
			 max_parallel: int = DEFAULT_MAX_PARALLEL) -> Estimate:
	"""Dispatch on ``cfg['type']`` (task / workflow / scan)."""
	ctype = (cfg or {}).get('type')
	if ctype == 'scan':
		return estimate_scan(cfg, opts, n_targets, calibration, registry, max_parallel)
	if ctype == 'workflow':
		return estimate_workflow(cfg, opts, n_targets, calibration, max_parallel)
	return estimate_task(cfg.get('name', ''), opts, n_targets, calibration, max_parallel)


# ---------------------------------------------------------------------------
# internals
# ---------------------------------------------------------------------------

def _walk_tasks(tasks: dict, opts, n_targets, calibration, max_parallel) -> list[Estimate]:
	"""Sequential list of estimates; a ``_``-group collapses to its max member."""
	out = []
	for key, value in (tasks or {}).items():
		if key.startswith('_'):
			members = _walk_tasks(value, opts, n_targets, calibration, max_parallel)
			if members:
				out.append(_max_estimate(members))
		elif not key.endswith('_'):  # skip "targets_" and other plumbing keys
			out.append(estimate_task(key, opts, n_targets, calibration, max_parallel))
	return out


def _lookup_calibration(task_name: str, calibration: dict | None) -> dict | None:
	if not calibration:
		return None
	c = calibration.get(task_name) or calibration.get(task_name.split('/')[0])
	if not c:
		return None
	p50 = _num(c.get('p50'))
	if p50 is None or (c.get('n') is not None and c['n'] < 3):
		return None
	return {'p50': p50, 'p90': _num(c.get('p90'), p50), 'n': _num(c.get('n'), 0)}


def _combine(t_algo, t_obs, calib) -> Estimate:
	"""Blend algorithmic and observed per the mixing strategy."""
	if t_algo is None and t_obs is None:
		return Estimate(0.0, 0.0, 0.0, 'empty')
	if t_obs is None:
		return Estimate(t_algo, t_algo * 0.6, t_algo * 2.5, 'algorithmic')
	if t_algo is None:
		# pure observed: range from p50..p90 ratio
		ratio = calib['p90'] / calib['p50'] if calib['p50'] else 2.5
		return Estimate(t_obs, t_obs * 0.7, t_obs * ratio, 'observed')
	w = min((calib['n'] or 0) / OBSERVED_TRUST_SAMPLES, OBSERVED_TRUST_CAP)
	seconds = w * t_obs + (1 - w) * t_algo
	# scale the observed p50..p90 spread by how far the algo pulls the point
	ratio = calib['p90'] / calib['p50'] if calib['p50'] else 2.5
	return Estimate(seconds, seconds * 0.6, seconds * max(ratio, 2.0), 'blended')


def _sum_estimates(parts: list[Estimate]) -> Estimate:
	if not parts:
		return Estimate(0.0, 0.0, 0.0, 'empty')
	return Estimate(
		sum(p.seconds for p in parts),
		sum(p.low for p in parts),
		sum(p.high for p in parts),
		_basis(parts),
	)


def _max_estimate(parts: list[Estimate]) -> Estimate:
	"""Parallel group: wall time is the slowest member (by point estimate)."""
	top = max(parts, key=lambda p: p.seconds)
	return Estimate(top.seconds, top.low, max(p.high for p in parts), _basis(parts))


def _basis(parts: list[Estimate]) -> str:
	bases = {p.basis for p in parts if p.basis != 'empty'}
	if not bases:
		return 'empty'
	if len(bases) == 1:
		return bases.pop()
	return 'blended'


def _demo():
	# all-ports + rate 1 + -sV must be "hours", top-1000 default must be "minutes"
	big = estimate_task('nmap', {'ports': '-', 'rate_limit': 1, 'version_detection': True}, 1)
	small = estimate_task('nmap', {'top_ports': 1000}, 1)
	assert big.seconds > 3600 and small.seconds < 1800, (big, small)
	# chunking: 100 targets over chunk=20 is ~5x one chunk, not 100x
	one = estimate_task('nuclei', {}, 20)
	many = estimate_task('nuclei', {}, 2000)
	assert many.seconds < one.seconds * 20, (one, many)
	# a parallel group <= sum of its tasks
	wf = {'tasks': {'_group/scan': {'nmap': {}, 'naabu': {}}, 'httpx': {}}}
	grp = estimate_workflow(wf, {}, 1)
	seq = estimate_workflow({'tasks': {'nmap': {}, 'naabu': {}, 'httpx': {}}}, {}, 1)
	assert grp.seconds <= seq.seconds, (grp, seq)
	# calibration blends toward the observed anchor for default opts
	calib = {'nmap': {'p50': 230.0, 'p90': 430.0, 'n': 300}}
	blended = estimate_task('nmap', {'top_ports': 1000}, 1, calib)
	assert blended.basis == 'blended' and blended.seconds > small.seconds, blended
	# human() is order-of-magnitude readable
	assert big.human().endswith('h') or big.human().endswith('d'), big.human()
	print('ok', small.human(), big.human(), blended.human())


if __name__ == '__main__':
	_demo()
