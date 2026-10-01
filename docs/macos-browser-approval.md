# macOS browser approval design and acceptance

This is the macOS slice of #1/#43. It preserves the existing separate human
browser profile and local plaintext boundary. Encrypted signup profiles and
Cloud relay are independent work. There are no profile or transfer schema changes.

## Trust boundary

The extension initiates a fill only from its own popup in the human profile.
Its button starts OS verification; it cannot itself approve disclosure. The
native host captures the pending request, closes the vault and invokes an
in-process Objective-C bridge linked to Apple's AppKit/LocalAuthentication.
A read-only, scrollable native window displays the full exact origin, project,
credential name, request ID, expiry and explicitly unverified agent labels.
Neither this window nor the extension provides an alternative approval button.

Every attempt creates a new `LAContext`, sets
`touchIDAuthenticationAllowableReuseDuration = 0`, hides the fallback button and
uses only `LAPolicyDeviceOwnerAuthenticationWithBiometrics`. There is no
`deviceOwnerAuthentication` password fallback, companion fallback, shell helper,
reusable bearer approval, environment bypass or agent-supplied success value.
Unavailable, unenrolled or locked-out Touch ID fails closed. Capability listing
uses `canEvaluatePolicy` without opening a prompt; availability may change before
verification and is checked again. Enrollment and hardware configuration are the
user's responsibility, outside the installer.

The reply block runs on Apple's private queue; a semaphore publishes its boolean
result. A bounded main-thread event loop processes window close events. Cancellation,
window close or timeout invalidates the context, and a late callback cannot change
the returned denial. The maximum wait is 110 seconds, shortened to the request's
remaining lifetime. The host then reopens the unlocked session and uses the
existing transaction to compare every request field (including expiry), exact
HTTPS origin, credential identity/revision, eligibility and pending one-use state
before decrypting. OS approval does not override vault lock, expiration, revocation,
changed metadata, form/navigation checks or a concurrent earlier release.

Cancel, refusal and backend failure deny the pending request without decrypting;
expiry may instead leave it failed. Audit events record existing bounded metadata,
never OS error text, biometric data, requester/reason strings or login payloads.
A failed audit prevents release. Neither cancellation nor fill failure removes or
activates the saved login. Completion still means fields filled, never submitted.

Same-owner malicious code can tamper with binaries/vault state or observe a
controlled browser; this is not OS-account isolation or a cryptographic attestation
of the webpage. Existing owner plaintext-egress tools are unchanged. Install only
in a profile unavailable to the agent, and use OS-account/process isolation when
needed. No process identity claim is inferred from native-messaging argv.

## Automated suite and its limits

`python3 scripts/verify.py --suite native-host` covers the real native framing and
metadata-only protocol, origin mismatch, expired/denied/replayed requests,
credential changes, full snapshot mutation, cancellation/backend errors, lock,
audit redaction/failure and concurrent one-use release using synthetic vaults.
The outcome tests feed synthetic verifier results to the internal state machine;
there is no production configuration that selects a mock verifier. They do not
invoke or prove physical user presence. On macOS the real Objective-C bridge is
compiled and linked by Cargo. Python tests create only disposable installation
fixtures and never execute the fixture host or write a real browser manifest.

## Required human acceptance — NOT RUN by automated suites

Record commit, date, tester, macOS version, Mac/Touch ID hardware, browser/version,
and pass/fail/not-run. Use disposable synthetic logins and a human-controlled
profile. Do not record passwords, native-message payloads or prompt screenshots.

| Check | Expected result | Status |
| --- | --- | --- |
| Chrome, Edge and Firefox manual registration | Exact extension allowlist; native listing works only after explicit setup | Not run |
| Touch ID enrolled and available | Full metadata shown; successful biometric authorizes one fill | Not run |
| No Touch ID / not enrolled / locked out | Fill unavailable/refused; no alternate approval route | Not run |
| Recent biometric device unlock, then new request | Fresh biometric evaluation required, no cached unlock acceptance | Not run |
| Cancel OS prompt or close metadata window | No fill; request denied; saved login remains pending | Not run |
| Wait for timeout/expiry | Prompt dismissed; no fill; new request required | Not run |
| Lock vault, edit credential or change request during prompt | No payload released after verification | Not run |
| Navigate/change form during prompt | No fill into changed document/target | Not run |
| Successful login/two-password signup fill | Same saved password, correct origin/fields; no submit or consent changes | Not run |
| Replay completed/denied request | No second disclosure | Not run |
| Reopen popup; inspect MCP status/audit | Metadata only; no login payload or untrusted labels in audit | Not run |
| Remove selected manifest and extension | Native handoff no longer connects; no background service remains | Not run |

Do not automate these OS dialogs or change permissions, enrollment, Gatekeeper,
security settings or persistent access to pass acceptance. Release signing and
browser-store distribution are not implemented by this source preview.

Primary references: [Apple LAContext](https://developer.apple.com/documentation/localauthentication/lacontext),
[biometric-only policy](https://developer.apple.com/documentation/localauthentication/lapolicy/deviceownerauthenticationwithbiometrics),
[unlock reuse interval](https://developer.apple.com/documentation/localauthentication/lacontext/touchidauthenticationallowablereuseduration),
[Chrome native messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging),
[Firefox native messaging](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_messaging),
[Edge native messaging](https://learn.microsoft.com/en-us/microsoft-edge/extensions/developer-guide/native-messaging).
