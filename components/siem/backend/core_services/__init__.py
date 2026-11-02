# Package shim to expose the `core-services` folder as the `core_services` import
import os
from pathlib import Path

# Add the sibling `core-services` directory to the package search path so imports
# like `import core_services.siem.app.main` resolve to `core-services/siem/...`.
pkg_root = Path(__file__).resolve().parent
core_services_dir = pkg_root.joinpath('..', 'core-services').resolve()
if core_services_dir.exists():
    __path__.append(str(core_services_dir))
