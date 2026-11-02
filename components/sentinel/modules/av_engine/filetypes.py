from pathlib import Path

MAGIC_TYPES = [
    (b"MZ", "windows_pe"),
    (b"PK\x03\x04", "zip_archive"),
    (b"%PDF", "pdf_document"),
    (b"\x7fELF", "elf_binary"),
    (b"\xca\xfe\xba\xbe", "java_class_or_macho"),
    (b"#!/", "script"),
]

SCRIPT_EXTENSIONS = {".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta", ".py", ".sh"}
DOCUMENT_EXTENSIONS = {".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm", ".rtf", ".pdf"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".iso", ".img", ".gz", ".tar"}
EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".scr", ".msi", ".com", ".cpl", ".jar"}


def detect_file_type(path: Path) -> str:
    try:
        head = path.open("rb").read(16)
    except Exception:
        head = b""
    for magic, name in MAGIC_TYPES:
        if head.startswith(magic):
            return name
    ext = path.suffix.lower()
    if ext in SCRIPT_EXTENSIONS:
        return "script"
    if ext in DOCUMENT_EXTENSIONS:
        return "document"
    if ext in ARCHIVE_EXTENSIONS:
        return "archive"
    if ext in EXECUTABLE_EXTENSIONS:
        return "executable"
    if ext in {".txt", ".log", ".csv", ".json", ".xml", ".html", ".htm"}:
        return "text"
    return "unknown"


def risky_extension(path: Path) -> bool:
    return path.suffix.lower() in SCRIPT_EXTENSIONS | EXECUTABLE_EXTENSIONS | ARCHIVE_EXTENSIONS
