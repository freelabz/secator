"""Numbered, idempotent store migrations, run on demand by ``secator migrate``.

Each migration module defines ``ID``, ``DESCRIPTION`` and ``run(backend, dry_run) -> (matched, changed)``
over the backend's store-wide primitives (``bulk_update``, ``ensure_index``). An applied migration is
stamped in the store itself, so it runs once per store.
"""
from datetime import datetime, timezone

from secator.migrations import m0001_target_fields

MIGRATIONS = [m0001_target_fields]


def run_migrations(backend, apply=False, force=False):
	"""Run the pending migrations on a store.

	Args:
		backend (QueryBackend): Store backend.
		apply (bool): Write the changes and stamp the migrations (dry run otherwise).
		force (bool): Re-run migrations already stamped as applied.

	Returns:
		list[dict]: One result per migration: ``id``, ``description``, ``status``, ``matched``, ``changed``.
	"""
	from secator.definitions import VERSION
	applied = backend.get_migrations()
	results = []
	for migration in MIGRATIONS:
		result = {'id': migration.ID, 'description': migration.DESCRIPTION}
		if migration.ID in applied and not force:
			results.append({**result, 'status': 'applied', **applied[migration.ID]})
			continue
		matched, changed = migration.run(backend, dry_run=not apply)
		result.update(matched=matched, changed=changed, status='done' if apply else 'pending')
		if apply:
			backend.set_migration(migration.ID, {
				'applied_at': datetime.now(timezone.utc).isoformat(),
				'version': VERSION,
				'matched': matched,
				'changed': changed,
			})
		results.append(result)
	return results
