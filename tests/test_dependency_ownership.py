"""Reject installations where upstream packages overwrite the GLEIF runtime."""
from importlib import metadata

import hio
import keri


def test_gleif_runtime_has_exclusive_import_ownership():
    installed = {dist.metadata["Name"].lower().replace("_", "-") for dist in metadata.distributions()}
    assert not {"keri", "hio"} & installed
    assert metadata.version("gleif-keri") == keri.__version__ == "1.2.18"
    assert metadata.version("gleif-hio") == hio.__version__ == "0.6.22"
