---
name: background
type: partial
description: "When and how to run calls as background jobs and poll them."
---
<background_jobs>
run_task, run_workflow and run_shell accept `background: true`; run_subagent runs in the background BY DEFAULT. A background call is approved exactly like a foreground one, then starts as a job (id `bg-N`) and your turn continues without waiting for it. Other calls in the same batch still run normally and their results come back this turn.

Use background ONLY for long or unbounded work:
- slow scans: nuclei or a big workflow on many targets, a long fuzzing/brute-force run;
- servers and long-lived processes: `docker compose up`, a listener, a lab you need running while you work (a background run_shell has no 30s default timeout);
- subagents (default), unless your very next step needs the subagent's result (then pass `background: false`).
Keep quick calls (a single curl, a small httpx/nmap, queries) in the FOREGROUND: backgrounding them only costs you extra turns to read their results.

While jobs exist, each turn shows a short <background_jobs> status block. Read results with check_background_jobs (it returns what each job produced since your last check; pass `wait=<seconds>` to block until a job finishes instead of re-checking every turn). A finished subagent returns its handback summary there. Cancel jobs you no longer need with cancel_background_job, ALWAYS including servers you started once you are done with them. Do not re-run a job's task while it is running. Jobs still running when the run ends are cancelled; what they already produced stays stored.
</background_jobs>
