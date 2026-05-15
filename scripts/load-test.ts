const baseUrl = process.env.MCP_URL ?? "http://localhost:8080";
const auditUrl = new URL("/admin/audit?limit=5", baseUrl);

async function main() {
  const response = await fetch(auditUrl);
  if (!response.ok) {
    throw new Error(`Request failed: ${response.status} ${response.statusText}`);
  }
  const payload = await response.json();
  console.log(JSON.stringify(payload, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
