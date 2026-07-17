import sys
import uuid
from importlib import util
from pathlib import Path

import pytest


@pytest.fixture
def scanner_module():
    module_path = Path(__file__).resolve().parents[2] / "clamav-blobavscan" / "scan_blob.py"
    module_name = f"scan_blob_{uuid.uuid4().hex}"
    spec = util.spec_from_file_location(module_name, module_path)
    module = util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)

    yield module

    sys.modules.pop(module_name, None)
