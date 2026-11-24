---
name: background
type: partial
description: "When and how to run calls as background jobs and poll them."
---
<background_jobs>
run_task, run_workflow and run_shell accept `background: true`. A background call is approved exactly like a foreground one, then starts as a job (id `bg-N`) and your turn continues without waiting for it. Other calls in the same batch still run normally and their results come back this turn.

Use background ONLY for long or unbounded work:
- slow scans: nuclei or a big workflow on many targets, a long fuzzing/brute-force run;
- servers and long-lived processes: `docker compose up`, a listener, a lab you need running while you work (a background run_shell has no 30s default timeout).
Keep quick calls (a single curl, a small httpx/nmap, queries) in the FOREGROUND: backgrounding them only costs you extra turns to read their results.

While jobs exist, each turn shows a short <background_jobs> status block. Read results with check_background_jobs (it returns what each job produced since your last check; pass `wait=<seconds>` to block until a job finishes instead of re-checking every turn). Cancel jobs you no longer need with cancel_background_job, ALWAYS including servers you started once you are done with them. Do not re-run a job's task while it is running.

Do not wait idle for a running job: start investigating what it found so far. check_background_jobs lists each job's `runners` (`id`, `type`, `query`) as soon as they start, and query_workspace(query=<a runner's `query`>) reads that runner's stored findings so far (e.g. query_workspace(query={"_context.task_id": "<id from query>"})). They are PARTIAL until the job is done: re-query later for new ones (add `"_timestamp": {"$gt": <newest _timestamp you already read>}` to get only those) and never re-run the task to see them.

When a job has FINISHED (the status block says so), read it with check_background_jobs and REPORT it in your next message to the user: which job, what it found, and your analysis of what it means and what to do next (e.g. "Subagent 'Exploit the Apache path traversal' finished and confirmed CVE-2021-41773 on 10.0.0.9: arbitrary file read works; next I will ..."). Never let a finished job pass silently. Jobs still running when the run ends are cancelled; what they already produced stays stored.
<background_subagents>
run_subagent runs in the background BY DEFAULT: you keep working while the subagent runs, and its handback (summary + what it persisted) comes back through check_background_jobs once it finishes. Pass `background: false` only when your very next step needs the subagent's result.
</background_subagents>
</background_jobs>
