# Decommission and reinstate a device

Open Devices and choose Decommissioned in the status filter. Open the device to
read its retained history, then choose Reinstate device (configuration permission
required). Download the reinstatement installer and run it as administrator on
the original endpoint. Refresh the page after enrollment succeeds.

The installer contains a credential bound to the original device ID and customer.
It expires after 24 hours and allows one successful enrollment. Generating another
reinstatement installer revokes the previous one. Enrollment checks the original
platform and serial number when the stored serial is present. Without a stored
serial, possession of the device-bound installer is the recovery authorization;
only give it to the administrator of the intended endpoint.

The device stays decommissioned until enrollment succeeds. Success restores the
original record and linked CMDB asset, retains group/policy/history, rotates agent
and DNS credentials, and records an audit event. Cancelled work is not replayed.
Old API credentials are never re-enabled. Generic enrollment tokens cannot
reactivate a retired record matched by serial; use this dedicated recovery flow.

This does not uninstall software or release network isolation. If isolation is
still active, restore connectivity as appropriate before enrollment and then
use the normal release action. Existing retention policies continue to apply.

Reinstatement uses the existing server-built Windows/Linux packages; macOS
remains unavailable until installable agent packaging is supplied. No agent source
changes are required. Backend tests simulate installer output and enrollment;
actual installer/repair execution must still be checked on a Windows test endpoint.
