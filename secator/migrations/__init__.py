"""Idempotent store migrations, run on demand by ``secator migrate``."""
from secator.migrations import m0001_target_fields

MIGRATIONS = [m0001_target_fields]
