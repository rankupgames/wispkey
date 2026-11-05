import { meaningfulHosts } from "./hosts.js";

export function createCredentialEntry({ session, request, feedback, fail, loadProjects, requestedView }) {
  const form = $state({ name: "", type: "bearer_token", value: "", project: "", partition: "", hosts: "", description: "", tags: "", header_name: "", param_name: "", username: "", url: "", name_prefix: "", application_key: "", application_secret: "", consumer_key: "" });
  let mode = $state(requestedView === "login" ? "website_login" : "single");
  let revealSecret = $state(false);
  let destinationConfirmed = $state(false);
  let partitions = $state([]);

  function clearSecrets() {
    revealSecret = false;
    form.value = "";
    form.username = "";
    form.application_key = "";
    form.application_secret = "";
    form.consumer_key = "";
    destinationConfirmed = false;
  }

  async function loadPartitions(name) {
    if (!name) { partitions = []; return; }
    const epoch = session.generation;
    const response = await request("list_partitions", { project: name });
    if (epoch !== session.generation || name !== form.project) return;
    if (!response.ok) { partitions = []; fail(response); return; }
    if (!Array.isArray(response.result.partitions)) { feedback.message = "Invalid environment list"; return; }
    partitions = response.result.partitions;
    if (!form.partition && partitions.length === 1) {
      form.partition = partitions[0].name;
      destinationConfirmed = false;
    }
  }

  async function createScope(kind) {
    const name = kind === "project" ? form.project : form.partition;
    if (!name.trim()) { feedback.message = "Enter a name before creating it"; return; }
    const response = await request(kind === "project" ? "create_project" : "create_partition", kind === "project" ? { name, destination_confirmed: true } : { project: form.project, name, destination_confirmed: true });
    if (!response.ok) { fail(response); return; }
    await loadProjects();
    await loadPartitions(form.project);
    feedback.notice = kind === "project" ? "Project created" : "Environment created";
    feedback.mutationNotice = feedback.notice;
  }

  async function saveCredential(event) {
    event.preventDefault();
    if (session.busy) return;
    feedback.message = "";
    feedback.notice = "";
    if (!destinationConfirmed || !form.project || !form.partition) { feedback.message = "Confirm the destination before saving"; return; }
    if ((mode === "ovh_api" || (mode === "single" && form.type !== "api_key")) && !meaningfulHosts(form.hosts)) { feedback.message = "Enter a hostname or a bounded host pattern"; return; }
    const owner = session.begin();
    const savedLogin = mode === "website_login";
    let method;
    let params;
    if (mode === "website_login") {
      method = "generate_login";
      params = { name: form.name, username: form.username, url: form.url, project: form.project, partition: form.partition, destination_confirmed: true };
    } else if (mode === "ovh_api") {
      method = "add_template";
      params = { template: "ovh_api", name_prefix: form.name_prefix, application_key: form.application_key, application_secret: form.application_secret, consumer_key: form.consumer_key, hosts: form.hosts, tags: form.tags, project: form.project, partition: form.partition, destination_confirmed: true };
    } else {
      method = "add_credential";
      params = { name: form.name, type: form.type, value: form.value, project: form.project, partition: form.partition, hosts: form.hosts, description: form.description, tags: form.tags, header_name: form.header_name, param_name: form.param_name, destination_confirmed: true };
    }
    const epoch = session.generation;
    const response = await request(method, params);
    if (epoch === session.generation) clearSecrets();
    session.finish(owner);
    if (!response.ok) { if (epoch === session.generation) fail(response); else feedback.message = "The save failed. Check its result before retrying."; return; }
    feedback.notice = savedLogin ? "Login saved" : "Saved";
    feedback.mutationNotice = feedback.notice;
  }

  return {
    form,
    get mode() { return mode; }, set mode(value) { mode = value; },
    get revealSecret() { return revealSecret; }, set revealSecret(value) { revealSecret = value; },
    get destinationConfirmed() { return destinationConfirmed; }, set destinationConfirmed(value) { destinationConfirmed = value; },
    get partitions() { return partitions; },
    clearSecrets, loadPartitions, createScope, saveCredential,
  };
}
