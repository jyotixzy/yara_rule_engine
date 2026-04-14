"""Package description: Ye package EML parse karke attachments nikalta hai, unhe unpack karta hai, aur YARA se scan karta hai."""

# Ye package ka simple public entrypoint hai, taaki bahar se direct pipeline call ki ja sake.
from .pipeline import run_pipeline

__all__ = ["run_pipeline"]
