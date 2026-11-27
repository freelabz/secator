---
name: background
type: partial
description: "When and how to run calls as background jobs and poll them."
---
<background_jobs>
run_task, run_workflow and run_shell accept `background: true`. A background call is approved exactly like a foreground one, then starts as a job (id `bg-N`) and your turn continues without waiting for it. Other calls in the same batch still run normally and their results come back this turn.

Use background ONLY for long or unbounded work:
- slow scans: nuclei or a big workflow on many targets, a long fuzzing/brute-force run;
- servers and long-lived processes: `docker compose up`, a listener, a lab you need running while you work (a background run_shell has no 30s default timeout: it runs until you cancel it, up to the max task run time when one is configured, then it is killed and its job shows "timed out after Ns").
Keep quick calls (a single curl, a small httpx/nmap, queries) in the FOREGROUND: backgrounding them only costs you extra turns to read their results.

Background jobs have no timeout of their own: a job runs until it finishes or you cancel it. While jobs exist, you see their status in a short <background_jobs> block at the start of each turn. Do not comment on jobs that are still running: keep working on the request. Read results (partial while running) with check_background_jobs; it returns what each job produced since your last check. The user may ask you to re-check (e.g. "So?"): look at the status block and report what finished. Cancel jobs you no longer need with cancel_background_job, ALWAYS including servers you started once you are done with them. Do not re-run a job's task while it is running.

When a job has FINISHED (the status block says so), read it with check_background_jobs and REPORT it in your next message to the user: which job, what it found, and your analysis of what it means and what to do next (e.g. "Subagent 'Exploit the Apache path traversal' finished and confirmed CVE-2021-41773 on 10.0.0.9: arbitrary file read works; next I will ..."). Never let a finished job pass silently. Jobs still running when the run is stopped are cancelled; what they already produced stays stored. In a run with no user (autonomous), calling stop ends the run and cancels the jobs still running: to wait for them, end your turn with a plain message instead, and you get a turn once one finishes.
<background_subagents>
run_subagent runs in the background BY DEFAULT: you keep working while the subagent runs, and its handback (summary + what it persisted) comes back through check_background_jobs once it finishes. Pass `background: false` only when your very next step needs the subagent's result.
</background_subagents>
</background_jobs>
