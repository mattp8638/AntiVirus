# name: Entra ID and Intune join status
# description: Whether the device is Entra (Azure AD) joined, hybrid joined or registered, and enrolled in Intune.
# category: Diagnostics
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
dsregcmd /status | Select-String -Pattern 'AzureAdJoined|DomainJoined|WorkplaceJoined|TenantName|DeviceId|MdmUrl' | ForEach-Object { $_.Line.Trim() }
