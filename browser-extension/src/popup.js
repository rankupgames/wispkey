const api = globalThis.browser || globalThis.chrome;
const status = document.querySelector("#status");
const requests = document.querySelector("#requests");
const human = document.querySelector("#human");
async function call(message) {
  const response = await api.runtime.sendMessage(message);
  if (!response?.ok) throw new Error(response?.error || "WispKey is unavailable.");
  return response.result;
}
async function refresh() {
  requests.replaceChildren();
  try {
    const result = await call({ method: "pending" });
    document.querySelector("#origin").textContent = result.origin;
    status.textContent = result.status || (result.requests.length ? "Choose a request to review." : "No pending requests for this origin.");
    for (const request of result.requests) {
      const article = document.createElement("article");
      for (const text of [
        `${request.project} / ${request.name}`,
        `Origin: ${request.origin}`,
        `Agent label (unverified): ${request.requester}`,
        `Reason (unverified): ${request.reason}`,
        `Expires: ${new Date(request.expires_at * 1000).toLocaleTimeString()}`,
      ]) {
        const paragraph = document.createElement("p");
        paragraph.textContent = text;
        article.append(paragraph);
      }
      const approve = document.createElement("button");
      approve.textContent = "Approve with Windows Hello";
      approve.disabled = !human.checked || !result.approval_available;
      approve.dataset.approval = String(result.approval_available);
      approve.addEventListener("click", async () => {
        if (!human.checked) return;
        approve.disabled = true;
        try { status.textContent = (await call({ method: "fill", request_id: request.request_id })).status; }
        catch (error) { status.textContent = error.message; }
      });
      const deny = document.createElement("button");
      deny.textContent = "Deny";
      deny.addEventListener("click", async () => {
        try { await call({ method: "deny", request_id: request.request_id }); await refresh(); }
        catch (error) { status.textContent = error.message; }
      });
      article.append(approve, deny);
      requests.append(article);
    }
  } catch (error) { status.textContent = error.message; }
}
human.addEventListener("change", () => {
  for (const button of requests.querySelectorAll("[data-approval]")) {
    button.disabled = !human.checked || button.dataset.approval !== "true";
  }
});
document.querySelector("#refresh").addEventListener("click", refresh);
void refresh();
