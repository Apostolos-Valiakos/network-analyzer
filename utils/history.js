// Formatting for the History page's tables and result dialog.
import { formatBytes } from "./format";

export function formatDate(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString();
}

// Same units as the rest of the UI (utils/format); a missing size is "—".
export function formatSize(bytes) {
  if (!bytes) return "—";
  return formatBytes(bytes);
}

export function statusColor(status) {
  if (!status) return "grey";
  const colors = { COMPLETED: "success", PROCESSING: "warning", PENDING: "grey", ERROR: "error" };
  return colors[status.toUpperCase()] || "grey";
}

export function formatConfidence(value) {
  if (value == null) return "—";
  return `${(value * 100).toFixed(0)}%`;
}

// Table columns. Admins also see who owns each row.
export function pcapHeaders(isAdmin) {
  const headers = [
    { text: "File", value: "original_filename", sortable: true },
    { text: "Uploaded", value: "upload_time", sortable: true },
    { text: "Size", value: "file_size", sortable: true },
    { text: "Status", value: "status", sortable: false },
    { text: "Actions", value: "actions", sortable: false, align: "right" },
  ];
  if (isAdmin) headers.splice(4, 0, { text: "User", value: "username", sortable: true });
  return headers;
}

export function clusterHeaders(isAdmin) {
  const headers = [
    { text: "Source PCAP", value: "original_filename", sortable: true },
    { text: "Created", value: "created_at", sortable: true },
    { text: "Actions", value: "actions", sortable: false, align: "right" },
  ];
  if (isAdmin) headers.splice(2, 0, { text: "User", value: "username", sortable: true });
  return headers;
}
