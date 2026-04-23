"""Checkpoint module for pause/resume support."""
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

CHECKPOINT_FILE = 'checkpoint.json'
CELERY_CHECKPOINT_PREFIX = 'checkpoint:'


@dataclass
class Checkpoint:
    runner_type: str          # 'task', 'workflow', 'scan'
    runner_id: str            # original runner UUID (for result re-association)
    runner_name: str          # e.g. 'nmap'
    targets: List[str]        # all original targets
    opts: Dict                # run options
    context: Dict             # full runner context
    completed_inputs: List[str] = field(default_factory=list)
    pause_method: str = 'kill'  # 'signal' or 'kill'
    process_pid: Optional[int] = None
    paused_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    # Native tool resume files: task_name -> local path to resume file
    resume_files: Dict[str, str] = field(default_factory=dict)
    # Workflow/Scan only
    task_states: Dict[str, str] = field(default_factory=dict)  # task_name -> 'completed'|'running'|'pending'
    completed_results_count: int = 0

    @property
    def remaining_inputs(self) -> List[str]:
        """Inputs not yet completed — used when restarting after kill-based pause."""
        if not self.completed_inputs:
            return list(self.targets)
        completed_set = set(self.completed_inputs)
        return [t for t in self.targets if t not in completed_set]

    def save(self, folder) -> Path:
        """Write checkpoint.json to the given folder."""
        path = Path(folder) / CHECKPOINT_FILE
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as f:
            json.dump(asdict(self), f, indent=2, default=str)
        return path

    @classmethod
    def load(cls, folder) -> Optional['Checkpoint']:
        """Load checkpoint.json from the given folder. Returns None if not found."""
        path = Path(folder) / CHECKPOINT_FILE
        if not path.exists():
            return None
        with open(path) as f:
            data = json.load(f)
        return cls(**data)

    def delete(self, folder):
        """Remove checkpoint.json from the given folder."""
        path = Path(folder) / CHECKPOINT_FILE
        if path.exists():
            path.unlink()
