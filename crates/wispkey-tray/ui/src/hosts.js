// The native boundary performs full validation; the form requires a meaningful
// host restriction before it can request a credential release path.
export function meaningfulHosts(value) {
  return value.split(",").map((host) => host.trim()).filter(Boolean).some((host) => /[a-zA-Z0-9]/.test(host));
}
