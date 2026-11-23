const CSV_HEADERS = [
  "Host",
  "Hostname",
  "Host State",
  "Port",
  "Protocol",
  "Port State",
  "Service",
  "Version",
  "CVEs",
];

function escapeCsv(value) {
  const str = value === null || value === undefined ? "" : String(value);
  return /[",\n]/.test(str) ? `"${str.replace(/"/g, '""')}"` : str;
}

// One row per open port; a host with no open ports still gets one row.
export function scanResultsToCsv(results) {
  const rows = [CSV_HEADERS];
  results.forEach((host) => {
    const ports = host.ports && host.ports.length ? host.ports : [{}];
    ports.forEach((port) => {
      rows.push([
        host.host,
        host.hostname || "",
        host.state || "",
        port.port ?? "",
        port.protocol || "",
        port.state || "",
        port.service || "",
        port.version || "",
        (port.cves || []).join("; "),
      ]);
    });
  });
  return rows.map((row) => row.map(escapeCsv).join(",")).join("\r\n");
}
