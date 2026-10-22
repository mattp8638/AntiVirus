import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(name)s - %(message)s"
)

def get_logger(name: str) -> logging.Logger:
    """Return a logger with the given module name."""
    return logging.getLogger(name)
