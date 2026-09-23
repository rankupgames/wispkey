import { mkdir, copyFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = path.dirname(fileURLToPath(import.meta.url));
for (const family of ["chromium", "firefox"]) {
  const out = path.join(root, "dist", family);
  await mkdir(out, { recursive: true });
  for (const file of ["background.js", "flow.js", "popup.js", "popup.html", "popup.css"]) {
    await copyFile(path.join(root, "src", file), path.join(out, file));
  }
  const manifest = {
    manifest_version: 3,
    name: "WispKey local login handoff",
    version: "0.4.0",
    description: "Approve one-time login fills in a separate human-controlled browser profile.",
    permissions: ["nativeMessaging", "activeTab", "scripting"],
    action: { default_popup: "popup.html", default_title: "WispKey login requests" },
    ...(family === "chromium"
      ? { minimum_chrome_version: "106", background: { service_worker: "background.js" } }
      : {
          background: { scripts: ["flow.js", "background.js"] },
          browser_specific_settings: { gecko: { id: "browser-handoff@wispkey.local", strict_min_version: "128.0", data_collection_permissions: { required: ["none"] } } },
        }),
  };
  await writeFile(path.join(out, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n");
}
