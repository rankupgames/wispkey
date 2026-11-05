# Desktop design

[Paper source](https://app.paper.design/file/01M3FEACTDT4SF44FVZRZQK8P4/p-4-0).
The Desktop page owns the approved 460px dark popout. The System page owns its shared parts.
Account, organization, provider and Cloud views remain outside the local desktop implementation.

| Paper views | Implementation |
| --- | --- |
| A1–A4 intake, file drop and input actions; A6 navigation | `crates/wispkey-tray/ui/src/Intake.svelte`, `App.svelte`, `app.css`, `Icon.svelte` |
| A5 credentials and Recent filter | `Credentials.svelte`, `inventory.svelte.js` |
| B1–B3 unlock, invalid password and first vault | `Unlock.svelte`, `App.svelte` vault status and unlock |
| C1–C2 credential entry and host validation | `AddCredential.svelte`, `credential-entry.svelte.js`, `hosts.js` |
| D1–D5 scan, metadata review, stored, tokenized and source failure | `Intake.svelte`, `intake.svelte.js` |

The UI uses Svelte 5 and custom CSS tokens exported from Paper. It embeds into one HTML file.
The native host owns clipboard, file selection, file drops and popout placement. The CLI owns vault and import operations.
`ipc.js` supplies bounded correlated requests; responses contain metadata and typed results, not secret values.
`App.svelte` composes per-popout controllers. `session.svelte.js` owns request epochs,
operation ownership, result redaction and the host callback/timer lifetime. Navigation
and privacy events invalidate stale replies; an active mutation stays busy until its
own reply settles. An abandoned preview cancels its native plan, including a late plan.

The inventory project filter belongs to `inventory.svelte.js`. Credential entry and
intake each own a destination and confirmation. All start in the active project;
changing an inventory filter never changes a save destination. Native token copy
remains metadata-only in the renderer. Late import results retain counts and a
source-failure flag while source paths and messages are removed.

The desktop screenshot in Paper is presentation context, not an application asset.
