"""Black-box helpers shared by the acceptance directories (imported as `from common import ...`).

They drive the product only through its public surfaces: the `ostia` binary, the JSON schemas, the public
fixture generators of `tests/fixtures/` and the fakes of `tests/fakes/`. Code that does not exist yet is
imported lazily, so collection succeeds before anything is implemented and the test fails at run time
with the reason.
"""

from common.archives import build_archive, gzip_bytes, tar_bytes, zip_bytes
from common.content import pdf_bytes, pe_bytes, png_bytes, seeded_bytes, sha1, sha256, text_bytes
from common.engines import fake_engine_config, on_sha256
from common.images import (
    FILE_SYSTEMS,
    Planted,
    blank_image,
    build_image,
    damaged_copy,
    minix_image,
)
from common.ostia import REPO, load_report, ostia_bin, run_ostia
from common.policy import (
    SignedPolicy,
    new_key,
    policy_document,
    write_signed_policy,
)
from common.scan import Scan, scan

__all__ = [
    "FILE_SYSTEMS",
    "REPO",
    "Planted",
    "Scan",
    "SignedPolicy",
    "blank_image",
    "build_archive",
    "build_image",
    "damaged_copy",
    "fake_engine_config",
    "gzip_bytes",
    "load_report",
    "minix_image",
    "new_key",
    "on_sha256",
    "ostia_bin",
    "pdf_bytes",
    "pe_bytes",
    "png_bytes",
    "policy_document",
    "run_ostia",
    "scan",
    "seeded_bytes",
    "sha1",
    "sha256",
    "tar_bytes",
    "text_bytes",
    "write_signed_policy",
    "zip_bytes",
]
