"""Facade exposing the wordlist based bruteforce utilities.

This module allows external code to import a single namespace providing both
``brute_force_paths`` and ``brute_force_files`` without worrying about the
underlying module layout.
"""

from directory_bruteforce import brute_force_paths
from file_bruteforce import brute_force_files

__all__ = ["brute_force_paths", "brute_force_files"]
