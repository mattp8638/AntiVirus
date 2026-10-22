import importlib
import os
from pathlib import Path
from logging_config import get_logger
logger = get_logger(__name__)

class ReconController:
    def __init__(self):
        self.modules = {}
        self.load_modules()

    def load_modules(self):
        base_path = Path(__file__).parent / "active_reconnaissance"
        for folder in os.listdir(base_path):
            folder_path = base_path / folder
            if folder_path.is_dir() and (folder_path / "__init__.py").exists():
                try:
                    module_name = f"reconnaissance.active_reconnaissance.{folder}.{folder}"
                    module = importlib.import_module(module_name)
                    self.modules[folder] = module
                except Exception as e:
                    logger.info(f"Error loading module {folder}: {e}")

    def run_module(self, module_name, *args, **kwargs):
        if module_name not in self.modules:
            return {"error": f"Module '{module_name}' not found."}
        
        module = self.modules[module_name]
        if hasattr(module, "main"):
            try:
                return module.main(*args, **kwargs)
            except Exception as e:
                return {"error": f"Error running module '{module_name}': {e}"}
        else:
            return {"error": f"Module '{module_name}' does not have a 'main' function."}

    def run_all(self, target_ip, subnet=None):
        results = {}
        for module_name, module in self.modules.items():
            if hasattr(module, "main"):
                try:
                    if module_name == "network_mapper":
                        results[module_name] = module.main(subnet)
                    else:
                        results[module_name] = module.main(target_ip)
                except Exception as e:
                    results[module_name] = {"error": f"Error running module '{module_name}': {e}"}
            else:
                results[module_name] = {"error": f"Module '{module_name}' does not have a 'main' function."}
        return results
