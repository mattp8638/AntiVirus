# Windows remote Ctrl+Alt+Del

The desktop toolbar's **Ctrl+Alt+Del** action must reach the Windows session being viewed. Ordinary injected keys cannot produce the Windows Secure Attention Sequence (SAS).

## What was wrong

The service-side broker called `SendSAS(FALSE)` from its own session 0 without impersonating the helper in the target desktop session. The helper also had a direct fallback that could report success when Windows ignored it: `SendSAS` has no return value. Errors were written to a status string that the live viewer did not display. Starting the broker after waiting for the helper to connect introduced an additional startup race.

## Implementation

- The service starts a per-session named-pipe broker immediately after launching the helper, before waiting for its relay connection.
- The pipe accepts local SYSTEM clients only. The service authenticates the exact launched helper process, its nonzero Windows session, its SYSTEM token and its impersonation level. It impersonates that helper while calling `SendSAS(FALSE)`, then reverts to its service context.
- The helper explicitly permits impersonation on this connection. It retries pipe startup within three seconds and bounds the request/reply exchange to five seconds. Cancelled overlapped I/O is completed before its buffers are released. A bounded acknowledgement replaces a potentially unbounded pipe flush.
- The helper never falls back to a direct `SendSAS` call. Replies echo the viewer's request ID. The viewer shows a pending state, a visible result or a ten-second timeout and prevents overlapping clicks.
- The existing relay and helper view-only restrictions remain enforced. Session events still audit `input.cad`.

The acknowledgement means the service issued the SAS request for the helper's session. The API cannot confirm that Windows displayed the credential prompt. Verify the screen transition on Windows before declaring a deployment validated.

## Deploy

1. Build and deploy the updated cloud/console image using the deployment's existing signing configuration.
2. Update **both** `fenrir-agent-service.exe` and `fenrir-remote.exe` on the Windows endpoint through the normal agent update or installer flow. Updating only the web console does not change Windows SAS behaviour. End old remote sessions and reconnect after the updated service starts.
3. Refresh the web console so the remote viewer loads its updated JavaScript.
4. Check the policy **Computer Configuration → Administrative Templates → Windows Components → Windows Logon Options → Disable or enable software Secure Attention Sequence**. Services must be permitted. Fenrir's existing service policy setup enables the services bit in `SoftwareSASGeneration`; if policy access fails, the viewer shows an error. Resolve centrally managed policy through the organisation's normal Group Policy process.

Keep the Windows requirement to press Ctrl+Alt+Del and enter credentials enabled. This action does not bypass authentication.

## Verification

Automated coverage:

- `RemoteSasRequestTests.cpp`: correct console/RDP session accepted; wrong process, wrong session, session 0, unknown session, non-SYSTEM token and insufficient impersonation rejected.
- `RemotePipeIoTests.cpp` (Windows): a silent peer times out, cancelled I/O is drained, a subsequent request succeeds and helper exit cancels a pending operation.
- `console/tests/remote-actions.test.mjs`: correlated acknowledgement, visible policy/service failures, invalid results, ignored late replies and legacy-agent feedback.
- `cloud/tests/test_remote.py`: correlated CAD request/result relay, audited request, and rejection of CAD input in view-only sessions.

Manual acceptance on a Windows Server VM:

1. Require Ctrl+Alt+Del for sign-in, lock the console and connect using Fenrir. Click the toolbar action immediately after connection. Confirm the screen changes to the credential prompt, enter credentials, then lock and repeat.
2. Repeat with the helper running in an active RDP session. Confirm its session receives the action and another signed-in session does not.
3. Stop or use an old service with the updated helper, then reconnect. Confirm the viewer shows a service-channel error or timeout and remains responsive.
4. On an isolated VM, prevent the service from changing the SAS policy and disallow service SAS. Confirm the viewer reports the policy failure. Restore the VM policy afterwards.
5. Connect in view-only mode. Confirm the action is disabled and a manually submitted CAD input is filtered by the relay.

References: [Microsoft SendSAS API](https://learn.microsoft.com/en-us/windows/win32/api/sas/nf-sas-sendsas), [Microsoft software SAS policy](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-winlogon#softwaresasgeneration).
