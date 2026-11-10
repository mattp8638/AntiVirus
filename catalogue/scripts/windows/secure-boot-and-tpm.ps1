# name: Secure Boot and TPM
# description: Whether Secure Boot is on and the TPM is present and ready.
# category: Security
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
try { "Secure Boot: $(Confirm-SecureBootUEFI)" } catch { 'Secure Boot: not supported or legacy BIOS' }
Get-Tpm | Format-List TpmPresent, TpmReady, TpmEnabled, ManufacturerVersion
