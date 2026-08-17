"""Throwaway: end-to-end scrub timing after the optimisations."""
import time
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

from core.file_source import load_upload
from core.pipeline import ScanOptions, scrub
from models.enums import Destination
from session.context import get_session_context
from utils.config import load_settings

session = get_session_context("bench-after", load_settings())
data = Path(r"c:\AI\large.txt").read_bytes()
loaded = load_upload(data, "large.txt", session)
print(f"input {loaded.bytes_total:,} bytes ({loaded.bytes_total / 1024:.0f} KB)")

for profile in ("DEFAULT_PII", "AI_SAAS"):
    start = time.time()
    r = scrub(
        loaded.handle,
        session,
        ScanOptions(profile_names=(profile,), destination=Destination.INTERNAL_SIEM),
    )
    elapsed = time.time() - start
    c = r.coverage
    print(
        f"\n{profile}"
        f"\n   time         {elapsed:.1f}s   ({loaded.bytes_total / 1024 / elapsed:.1f} KB/s)"
        f"\n   entities     {r.entity_count}"
        f"\n   status       {r.status}  refusal={r.refusal}"
        f"\n   coverage     {c.coverage_percent}%  chunks={c.chunks_processed}/{c.chunks_total}"
        f"  complete={c.is_complete()}"
        f"\n   artifact     {r.artifact_available}  verified={r.verified_clean}"
    )
