"""Rough duration estimation for runners, from run options.

Nothing is run and no network is used: given a task / workflow / scan config,
a ``run_opts`` dict and a target count, return an order-of-magnitude
``Estimate``. The point is a "seconds / minutes / hours / this-will-eat-your-
budget" signal, not a promise.

Each task has a model in ``TASK_MODELS``: either fixed seconds per target, or
requests / packets per target driven by the options (ports, wordlist, crawl
depth) divided by a rate. Workflows and scans are walked with the runner tree
(``build_runner_tree`` + ``prune_runner_tree``), so ``if:`` conditions are
honoured as when running: a group costs its slowest member, the rest chains.
Callers may pass an observed calibration (``{task: {"p50", "p90", "n"}}`` in
seconds per target); it is blended with the model, see ``_combine``.

Limitations: chunks are assumed to run in parallel on workers (not a sync
run), and every step is estimated for the same target count: steps fed by
discovered items (ports, URLs, subdomains) do not scale with what is found.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

from dotmap import DotMap

from secator.config import CONFIG
from secator.runners._helpers import chunking_needed, get_task_overrides
from secator.runners.task import Task
from secator.template import TemplateLoader
from secator.tree import build_runner_tree, get_flat_node_list, prune_runner_tree, strip_workflow_prefix
from secator.utils import merge_opts

# Observed averages are options-blind, so even with many samples the model
# keeps a 30% say and a divergent option choice can still move the estimate.
OBSERVED_TRUST_CAP = 0.7
OBSERVED_TRUST_SAMPLES = 30  # samples at which trust reaches the cap

DEFAULT_MAX_PARALLEL = 20    # concurrent chunks (order-of-magnitude, not a scheduler)
SETUP_S = 5.0                # per-chunk startup: process spawn, template / wordlist load
HTTP_RESPONSE_S = 0.5        # avg HTTP round trip: 50 threads ~ 100 req/s without a rate limit
ALL_PORTS = 65535
OPEN_PORTS = 10              # open ports a port-chained step (``ports_``) works on
CRAWL_BRANCHING = 15         # new in-scope links per crawled page: pages ~ 15 ** depth ...
CRAWL_MAX_PAGES = 10000      # ... up to what a site has in scope
DEFAULT_WORDLIST_LINES = 5000
WORDLIST_LINES = {           # line counts of the wordlists in CONFIG.wordlists.templates
	'bo0m_fuzz': 5384,
	'burp-parameter-names': 6453,
	'combined_subdomains': 653920,
	'directory_list_small': 87663,
}

# One model per task. Keys:
#   seconds  : fixed seconds per target (lookups, checks, test batteries), or
#   requests : requests / packets per target: a number, 'ports', 'wordlist' or 'crawl'
#   rate     : send rate (req/s) of tools whose rate_limit sets it; for the others the
#              pace is ``pace`` (default: threads / HTTP_RESPONSE_S) and rate_limit caps it
#   ports, wordlist, depth : the tool's own default for that option
#   sv_port_s: seconds of -sV probing per open port
#   filtered : share of requests left when templates are filtered (tags, severity...)
TASK_MODELS: dict[str, dict] = {
	# Port scanners. nmap -T3 (default timing) adapts to drops and retransmits up to
	# 10 times: ~75 probes/s on a filtered host, i.e. top-1000 in ~15s and all ports
	# in ~15 min; --max-rate only caps that. naabu sends 1000 pkt/s (-rate), masscan
	# 100 pkt/s (--max-rate), without -sV. masscan has no default port list: assume 1000.
	'nmap': {'requests': 'ports', 'ports': 1000, 'pace': 75, 'sv_port_s': 6},
	'naabu': {'requests': 'ports', 'ports': 100, 'rate': 1000},
	'masscan': {'requests': 'ports', 'ports': 1000, 'rate': 100},
	# Host discovery and local network helpers.
	'fping': {'seconds': 5},
	'arpscan': {'seconds': 10},
	'arp': {'seconds': 1},
	'netdetect': {'seconds': 1},
	'mapcidr': {'seconds': 0.1},
	'cidr_split': {'seconds': 0.1},
	'dublin_traceroute': {'seconds': 60},
	# DNS: plain resolution, or brute force when a wordlist is given.
	'dnsx': {'requests': 'wordlist', 'rate': 1000},
	# Passive lookups against third-party sources.
	'subfinder': {'seconds': 30},
	'gau': {'seconds': 30},
	'urlfinder': {'seconds': 30},
	'xurlfind3r': {'seconds': 30},
	'getasn': {'seconds': 2},
	'whois': {'seconds': 3},
	'whoisdomain': {'seconds': 3},
	'jswhois': {'seconds': 3},
	'h8mail': {'seconds': 20},
	'maigret': {'seconds': 120},
	'bbot': {'seconds': 1800},
	# HTTP probing and vulnerability checks.
	'httpx': {'requests': 2},
	'wafw00f': {'requests': 10},
	'bup': {'requests': 300},
	'apachetomcatscanner': {'requests': 50},
	'dockerregistrygrabber': {'requests': 20},
	'wpprobe': {'requests': 1000},
	'dalfox': {'requests': 1000},
	# nuclei: ~9k templates, ~45k requests at its default -rl 150: ~5 min per host.
	'nuclei': {'requests': 45000, 'rate': 150, 'filtered': 0.2},
	'eyewitness': {'seconds': 10},
	'testssl': {'seconds': 190},
	'wpscan': {'seconds': 60},
	'droopescan': {'seconds': 120},
	# Crawlers (katana and gospider default depths: 3 and 1).
	'katana': {'requests': 'crawl', 'depth': 3},
	'gospider': {'requests': 'crawl', 'depth': 1},
	'cariddi': {'requests': 500},
	# Fuzzers: one request per wordlist line. Parameter miners batch their wordlist.
	'ffuf': {'requests': 'wordlist', 'wordlist': 'http'},
	'feroxbuster': {'requests': 'wordlist', 'wordlist': 'http'},
	'arjun': {'seconds': 30},
	'x8': {'seconds': 60},
	# Per-service checks.
	'sshaudit': {'seconds': 10},
	'nxc_ftp': {'seconds': 15},
	'nxc_mssql': {'seconds': 15},
	'nxc_rdp': {'seconds': 15},
	'nxc_smb': {'seconds': 15},
	'rmg': {'seconds': 60},
	'beanshooter': {'seconds': 30},
	'jdwp_shellifier': {'seconds': 10},
	'nfswolf': {'seconds': 20},
	'zabbix_get': {'seconds': 5},
	'msfconsole': {'seconds': 120},
	'manspider': {'seconds': 600},
	# Local lookups and file / code scanners.
	'searchsploit': {'seconds': 3},
	'search_vulns': {'seconds': 5},
	'gitleaks': {'seconds': 15},
	'trufflehog': {'seconds': 15},
	'grype': {'seconds': 60},
	'trivy': {'seconds': 60},
	'gf': {'seconds': 0.1},
	'urlparser': {'seconds': 0.1},
	'ph': {'seconds': 2},
	# Agentic / interactive (a prompt waits on the user, it does no work).
	'ai': {'seconds': 600},
	'prompt': {'seconds': 0},
	'command': {'seconds': 5},
}


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


def estimate(config, opts: dict | None = None, n_targets: int = 1,
			 calibration: dict | None = None,
			 max_parallel: int = DEFAULT_MAX_PARALLEL) -> Estimate:
	"""Estimate a task, workflow or scan config (``TemplateLoader`` or dict)."""
	config = config if isinstance(config, DotMap) else TemplateLoader(config)
	opts = opts or {}
	if config.type == 'task':
		return estimate_task(config.name, opts, n_targets, calibration, max_parallel)
	tree = build_runner_tree(config)
	opts = _with_defaults(tree, opts)
	prune_runner_tree(tree, opts, [None] * max(1, n_targets))  # only len(targets) is known
	return _sum([_estimate_node(node, opts, n_targets, calibration, max_parallel) for node in tree.root_nodes])


def estimate_task(task_name: str, opts: dict | None, n_targets: int,
				  calibration: dict | None = None,
				  max_parallel: int = DEFAULT_MAX_PARALLEL) -> Estimate:
	"""Estimate one task over ``n_targets``, blended with ``calibration`` if any."""
	n_targets = max(1, int(n_targets or 1))
	base = task_name.split('/')[0]  # "nmap/light" -> "nmap"
	model = TASK_MODELS.get(base)
	t_model = None
	if model:
		chunk_size = get_task_overrides(base).get('input_chunk_size', Task.get_task_class(base).input_chunk_size)
		chunk_targets = chunk_size if chunking_needed(n_targets, False, chunk_size) else n_targets
		waves = math.ceil(math.ceil(n_targets / chunk_targets) / max(1, max_parallel))
		t_model = waves * (SETUP_S + target_seconds(base, opts or {}) * chunk_targets)
	calib = _lookup_calibration(task_name, calibration)
	t_obs = calib['p50'] * n_targets if calib else None
	return _combine(t_model, t_obs, calib)


def target_seconds(task_name: str, opts: dict) -> float:
	"""Seconds of work one target costs for ``task_name`` with ``opts``."""
	model = TASK_MODELS[task_name.split('/')[0]]
	if 'seconds' in model:
		return model['seconds']
	requests = _requests(model, opts)
	if model.get('filtered') and any(opts.get(k) for k in ('tags', 'severity', 'templates')):
		requests *= model['filtered']
	rate_limit = _num(opts.get('rate_limit'))
	if 'rate' in model:
		rate = rate_limit or model['rate']
	else:
		delay = _num(opts.get('delay'), 0)
		if 'pace' in model:  # one probe after another, delay between probes
			pace = 1 / (1 / model['pace'] + delay)
		else:  # threads in parallel, delay per thread
			pace = _num(opts.get('threads'), CONFIG.runners.threads) / (HTTP_RESPONSE_S + delay)
		rate = min(rate_limit or pace, pace)
	seconds = requests / rate
	if model.get('sv_port_s') and (opts.get('version_detection') or opts.get('detect_all')):
		seconds += OPEN_PORTS * model['sv_port_s']
	return seconds


def _requests(model: dict, opts: dict) -> float:
	kind = model['requests']
	if kind == 'ports':
		if opts.get('ping_scan'):
			return 1  # host discovery only
		if opts.get('ports_'):
			return OPEN_PORTS  # ports chained from a previous port scan
		return _port_count(opts, model['ports'])
	if kind == 'wordlist':
		name = opts.get('wordlist') or model.get('wordlist')
		if not name:
			return 1  # no wordlist: plain resolution
		name = CONFIG.wordlists.defaults[name] if name in CONFIG.wordlists.defaults else name
		return WORDLIST_LINES.get(name, DEFAULT_WORDLIST_LINES)
	if kind == 'crawl':
		return min(CRAWL_BRANCHING ** max(1, _num(opts.get('depth'), model['depth'])), CRAWL_MAX_PAGES)
	return kind


def _port_count(opts: dict, default: int) -> int:
	ports = opts.get('ports')
	if ports:
		if str(ports).strip() == '-':
			return ALL_PORTS
		total = 0
		for part in str(ports).split(','):  # "22,80,443" or "1-1024"
			lo, _, hi = part.strip().partition('-')
			try:
				total += int(hi) - int(lo) + 1 if hi else 1
			except ValueError:
				total += 1
		return total or default
	return int(_num(opts.get('top_ports'), default))


def _num(value, default=None):
	try:
		return default if value is None else float(value)
	except (TypeError, ValueError):
		return default


def _with_defaults(tree, opts: dict) -> dict:
	"""Add workflow option defaults (``<workflow>_<opt>``) the user did not set."""
	opts = dict(opts)
	for node in get_flat_node_list(tree):
		if node.type != 'workflow':
			continue
		prefix = node.name.split('/')[0] + '_'
		for key, conf in node.opts.items():
			if key not in opts and prefix + key not in opts and 'default' in conf:
				opts[prefix + key] = conf['default']
	return opts


def _estimate_node(node, opts, n_targets, calibration, max_parallel) -> Estimate:
	"""Task: its estimate. Group: slowest child. Workflow / scan: sum of children."""
	if node.type == 'task':
		task_opts = merge_opts(node.ancestor.default_opts, node.opts, opts)
		return estimate_task(node.name, task_opts, n_targets, calibration, max_parallel)
	if node.type == 'workflow':
		opts = strip_workflow_prefix(opts, node.name)
	parts = [_estimate_node(child, opts, n_targets, calibration, max_parallel) for child in node.children]
	if node.type == 'group' and parts:
		return Estimate(max(p.seconds for p in parts), max(p.low for p in parts), max(p.high for p in parts), _basis(parts))
	return _sum(parts)


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


def _combine(t_model, t_obs, calib) -> Estimate:
	"""Blend the model and the observed estimate, weighted by sample count."""
	if t_model is None and t_obs is None:
		return Estimate(0.0, 0.0, 0.0, 'empty')
	if t_obs is None:
		return Estimate(t_model, t_model * 0.6, t_model * 2.5, 'algorithmic')
	ratio = calib['p90'] / calib['p50'] if calib['p50'] else 2.5
	if t_model is None:
		return Estimate(t_obs, t_obs * 0.7, t_obs * ratio, 'observed')
	w = min((calib['n'] or 0) / OBSERVED_TRUST_SAMPLES, OBSERVED_TRUST_CAP)
	seconds = w * t_obs + (1 - w) * t_model
	return Estimate(seconds, seconds * 0.6, seconds * max(ratio, 2.0), 'blended')


def _sum(parts: list[Estimate]) -> Estimate:
	if not parts:
		return Estimate(0.0, 0.0, 0.0, 'empty')
	return Estimate(
		sum(p.seconds for p in parts),
		sum(p.low for p in parts),
		sum(p.high for p in parts),
		_basis(parts),
	)


def _basis(parts: list[Estimate]) -> str:
	bases = {p.basis for p in parts if p.basis != 'empty'}
	if not bases:
		return 'empty'
	return bases.pop() if len(bases) == 1 else 'blended'
