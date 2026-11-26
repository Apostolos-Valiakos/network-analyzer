// Hands a Blob to the browser as a file download.
export function saveBlob(blob, filename) {
  const objectUrl = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = objectUrl;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(objectUrl);
}

// Saves a fetch Response as `filename`. A failed response throws an Error
// with the server's {"error": ...} message, or `fallbackMessage` when the body
// has none, so every page shows the same text for the same failure.
export async function saveResponse(res, filename, fallbackMessage = "Download failed") {
  if (!res.ok) {
    let message = fallbackMessage;
    try {
      const body = await res.json();
      if (body && body.error) message = body.error;
    } catch (e) {
      // Not JSON (e.g. an HTML error page): keep the fallback message.
    }
    throw new Error(message);
  }
  saveBlob(await res.blob(), filename);
}
