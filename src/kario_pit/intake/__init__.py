"""Local-only, vendor-neutral, permission-aware pilot intake (v0.6)."""
from .vendor_neutral_v06 import IntakeError, import_local_file

__all__ = ["IntakeError", "import_local_file"]
