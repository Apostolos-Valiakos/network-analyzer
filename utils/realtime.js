// Helpers for the Real Time page: packets arrive from publisher.py as base64
// strings of raw Ethernet frames.

export function generateSessionId() {
  return (
    "session_" +
    Math.random().toString(36).substring(2, 9) +
    Date.now().toString(36)
  );
}

// Decoded size of a base64 string, as the page has always estimated it.
export function base64Size(base64Packet) {
  return Math.floor((base64Packet.length * 3) / 4);
}

// Source and destination of an Ethernet + IPv4 frame, or null for anything
// else (other EtherTypes, short or undecodable frames).
export function ipv4Endpoints(base64Packet) {
  let binary;
  try {
    binary = atob(base64Packet);
  } catch (e) {
    return null;
  }
  if (binary.length < 34) return null;
  const byte = (i) => binary.charCodeAt(i);
  if (byte(12) !== 0x08 || byte(13) !== 0x00) return null;
  const ip = (offset) =>
    `${byte(offset)}.${byte(offset + 1)}.${byte(offset + 2)}.${byte(offset + 3)}`;
  return { src: ip(26), dst: ip(30) };
}
