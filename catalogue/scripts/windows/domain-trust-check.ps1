# name: Domain trust check
# description: Whether this computer's secure channel with the domain works.
# category: Diagnostics
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
try { "Secure channel OK: $(Test-ComputerSecureChannel)" } catch { "Not domain joined or check failed: $($_.Exception.Message)" }
