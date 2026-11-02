import os
import importlib
from pathlib import Path
from logging_config import get_logger
logger = get_logger(__name__)

class ReconController:
    def __init__(self):
        """
        Initialize the ReconController by dynamically discovering and loading modules.
        """
        self.modules = {}
        self.load_modules()

    def load_modules(self):
        """
        Dynamically load all modules from the passive_reconnaissance subfolder.
        """
        base_path = Path(__file__).parent
        for folder in os.listdir(base_path):
            folder_path = base_path / folder
            if folder_path.is_dir() and (folder_path / "__init__.py").exists():
                try:
                    # Import the module dynamically
                    module_name = f"core.reconnaissance.passive_reconnaissance.{folder}.{folder}"
                    module = importlib.import_module(module_name)
                    self.modules[folder] = module
                except Exception as e:
                    logger.info(f"Error loading module {folder}: {e}")

    def run_module(self, module_name, *args, **kwargs):
        """
        Run a specific reconnaissance module by name.
        
        Args:
            module_name (str): The name of the module to run.
            *args, **kwargs: Arguments to pass to the module's main function.
        
        Returns:
            The result of the module's execution.
        """
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

    def run_all(self, target, *args, **kwargs):
        """
        Run all reconnaissance modules sequentially.
        
        Args:
            target (str): The target domain or keyword for reconnaissance.
            *args, **kwargs: Additional arguments to pass to each module.
        
        Returns:
            A dictionary containing results from all modules.
        """
        results = {}
        for module_name, module in self.modules.items():
            if hasattr(module, "main"):
                try:
                    logger.info(f"Running module: {module_name}")
                    results[module_name] = module.main(target, *args, **kwargs)
                except Exception as e:
                    results[module_name] = {"error": f"Error running module '{module_name}': {e}"}
            else:
                results[module_name] = {"error": f"Module '{module_name}' does not have a 'main' function."}
        return results

# Example usage
if __name__ == "__main__":
    # Initialize the controller
    controller = ReconController()

    # Example: Run a specific module
    target_domain = "example.com"
    result = controller.run_module("dns_enumeration", target_domain, record_type="A")
    logger.info(f"DNS Enumeration Result: {result}")

    # Example: Run all modules
    all_results = controller.run_all(target_domain)
    for module_name, module_result in all_results.items():
        logger.info(f"\nResults from {module_name}:")
        logger.info(module_result)
