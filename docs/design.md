# Desktop design

[Paper source](https://app.paper.design/file/01M3FEACTDT4SF44FVZRZQK8P4/p-4-0).
The Desktop page owns the approved 460px dark popout. The System page owns its shared parts.
Account, organization, provider and Cloud views remain outside the local desktop implementation.

| Paper views | Implementation |
| --- | --- |
| A1–A4 intake, file drop and input actions; A6 navigation | `crates/wispkey-tray/ui/src/App.svelte`, `app.css`, `Icon.svelte` |
| A5 credentials and Recent filter | `App.svelte` credential list |
| B1–B3 unlock, invalid password and first vault | `App.svelte` vault form |
| C1–C2 credential entry and host validation | `App.svelte` credential form |
| D1–D5 scan, metadata review, stored, tokenized and source failure | `App.svelte` import flow |

The UI uses Svelte 5 and custom CSS tokens exported from Paper. It embeds into one HTML file.
The native host owns clipboard, file selection, file drops and popout placement. The CLI owns vault and import operations.
`ipc.js` supplies bounded correlated requests; responses contain metadata and typed results, not secret values.
The desktop screenshot in Paper is presentation context, not an application asset.
