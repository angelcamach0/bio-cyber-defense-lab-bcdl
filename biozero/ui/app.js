// SPDX-License-Identifier: AGPL-3.0-only
// UI client logic: uploads files, polls results, sends alerts, and queries health
// endpoints; it talks to the API proxy in nginx and surfaces status to users.
const uploadBtn = document.getElementById("uploadBtn");
const alertBtn = document.getElementById("alertBtn");
const refreshHealth = document.getElementById("refreshHealth");
const uploadStatus = document.getElementById("uploadStatus");
const resultsBox = document.getElementById("resultsBox");
const jobMeta = document.getElementById("jobMeta");
const alertBox = document.getElementById("alertBox");
const maxFileBytes = 25 * 1024 * 1024;

const api = {
  upload: "/api/upload",
  results: "/api/results",
  alert: "/api/alert",
  healthUpload: "/api/health/upload",
  healthResults: "/api/health/results",
  healthZR: "/api/health/zeroresponder",
};

/// Template for function documentation
///
/// Brief description of what the function does.
///
/// Parameters:
///   [value] - Client identifier string to validate.
///
/// Returns true when the client ID matches the allowed pattern.
///
/// Throws [None] - pure validation.
///
/// Example: isValidClientId("researcher-1")
function isValidClientId(value) {
  // Return regex test result to enforce safe client ID format.
  return /^[A-Za-z0-9_-]{1,64}$/.test(value);
}

/// Template for function documentation
///
/// Brief description of what the function does.
///
/// Parameters:
///   [url] - API endpoint to call.
///   [options] - Fetch options (method, headers, body).
///   [timeoutMs] - Timeout in milliseconds.
///
/// Returns a fetch Response when successful.
///
/// Throws [AbortError] when the request exceeds timeout.
///
/// Example: await fetchWithTimeout("/api/health", {}, 5000)
async function fetchWithTimeout(url, options = {}, timeoutMs = 10000) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  try {
    // Return the fetch response to the caller for status handling.
    const resp = await fetch(url, { ...options, signal: controller.signal });
    return resp;
  } finally {
    // Clear timeout to avoid leaking timers.
    clearTimeout(timeoutId);
  }
}

/// Template for function documentation
///
/// Brief description of what the function does.
///
/// Parameters:
///   [file] - File object selected by the user.
///
/// Returns a hex-encoded SHA-256 hash string.
///
/// Throws [Error] when hashing fails.
///
/// Example: const hash = await hashFile(file)
async function hashFile(file) {
  const buf = await file.arrayBuffer();
  const hash = await crypto.subtle.digest("SHA-256", buf);
  const bytes = Array.from(new Uint8Array(hash));
  // Return a hex string for API header compatibility.
  return bytes.map((b) => b.toString(16).padStart(2, "0")).join("");
}

/// Template for function documentation
///
/// Brief description of what the function does.
///
/// Parameters:
///   None.
///
/// Returns no value; updates UI state and triggers result polling.
///
/// Throws [Error] when upload fails or validation fails.
///
/// Example: uploadBtn.addEventListener("click", uploadFile)
async function uploadFile() {
  const fileInput = document.getElementById("fileInput");
  const clientId = document.getElementById("clientId").value.trim();
  const file = fileInput.files[0];

  if (!clientId) {
    uploadStatus.textContent = "Client ID is required.";
    // Return early to avoid sending anonymous uploads.
    return;
  }
  if (!isValidClientId(clientId)) {
    uploadStatus.textContent = "Client ID must be 1-64 chars: letters, numbers, - or _.";
    // Return early to enforce safe ID format.
    return;
  }
  if (!file) {
    uploadStatus.textContent = "Select a FASTQ file.";
    // Return early to avoid null file uploads.
    return;
  }
  if (file.size > maxFileBytes) {
    uploadStatus.textContent = "File exceeds the 25MB limit.";
    // Return early to avoid server-side rejection.
    return;
  }

  uploadBtn.disabled = true;
  uploadStatus.textContent = "Hashing file...";

  try {
    const hash = await hashFile(file);
    const form = new FormData();
    form.append("file", file);
    form.append("client_id", clientId);

    uploadStatus.textContent = "Uploading...";
    const resp = await fetchWithTimeout(api.upload, {
      method: "POST",
      headers: {
        "X-Content-SHA256": hash,
        "X-Client-Id": clientId,
      },
      body: form,
    }, 20000);

    if (!resp.ok) {
      const text = await resp.text();
      uploadStatus.textContent = `Upload failed: ${text}`;
      uploadBtn.disabled = false;
      // Return early on failed uploads to avoid polling invalid jobs.
      return;
    }

    const data = await resp.json();
    const jobId = data.job_id;
    jobMeta.textContent = `Job ID: ${jobId}`;
    uploadStatus.textContent = "Upload complete. Polling results...";
    pollResults(jobId, clientId);
  } catch (err) {
    uploadStatus.textContent = `Error: ${err.message}`;
  } finally {
    // Re-enable the upload button after completion or failure.
    uploadBtn.disabled = false;
  }
}

/// Template for function documentation
///
/// Brief description of what the function does.
///
/// Parameters:
///   [jobId] - Job identifier to query.
///   [clientId] - Client identifier for authorization headers.
///
/// Returns no value; updates UI with results or errors.
///
/// Throws [Error] when result polling fails repeatedly.
///
/// Example: pollResults(jobId, clientId)
async function pollResults(jobId, clientId) {
  const url = `${api.results}/${jobId}`;
  let consecutiveErrors = 0;
  // Poll the results endpoint for a fixed number of attempts.
  for (let i = 0; i < 30; i += 1) {
    try {
      const resp = await fetchWithTimeout(url, {
        headers: {
          "X-Client-Id": clientId,
        },
      }, 10000);

      if (!resp.ok) {
        resultsBox.textContent = `Error: ${await resp.text()}`;
        // Return early when the API reports an error.
        return;
      }

      const data = await resp.json();
      if (data.status === "processed") {
        resultsBox.textContent = JSON.stringify(data, null, 2);
        uploadStatus.textContent = "Results ready.";
        // Return after displaying final results.
        return;
      }

      uploadStatus.textContent = "Processing...";
      await new Promise((r) => setTimeout(r, 2000));
      consecutiveErrors = 0;
    } catch (err) {
      consecutiveErrors += 1;
      if (consecutiveErrors >= 3) {
        resultsBox.textContent = `Error: ${err.message}`;
        // Return after repeated failures to avoid endless polling.
        return;
      }
      await new Promise((r) => setTimeout(r, 2000));
    }
  }

  uploadStatus.textContent = "Timed out waiting for results.";
}

/// Template for function documentation
///
/// Brief description of what the function does.
///
/// Parameters:
///   None.
///
/// Returns no value; updates UI with alert response.
///
/// Throws [Error] when the alert request fails.
///
/// Example: alertBtn.addEventListener("click", sendAlert)
async function sendAlert() {
  alertBtn.disabled = true;
  alertBox.textContent = "Sending alert...";

  const payload = {
    alert_id: `ALERT-${Date.now()}`,
    source: "ui",
    severity: "medium",
    timestamp: new Date().toISOString(),
    indicators: {
      ip: "10.1.2.3",
      job_id: "demo-job",
      cert_serial: "01",
    },
    actions: ["block_ip", "revoke_cert", "quarantine"],
  };

  try {
    const resp = await fetchWithTimeout(api.alert, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    }, 10000);

    if (!resp.ok) {
      alertBox.textContent = await resp.text();
      // Return early on non-OK responses to avoid parsing errors.
      return;
    }
    const data = await resp.json();
    alertBox.textContent = JSON.stringify(data, null, 2);
  } catch (err) {
    alertBox.textContent = `Error: ${err.message}`;
  } finally {
    // Re-enable alert button after request finishes.
    alertBtn.disabled = false;
  }
}

/// Template for function documentation
///
/// Brief description of what the function does.
///
/// Parameters:
///   None.
///
/// Returns no value; updates health badges in the UI.
///
/// Throws [Error] when health endpoints are unreachable.
///
/// Example: refreshHealth.addEventListener("click", checkHealth)
async function checkHealth() {
  const mappings = [
    { key: "upload", url: api.healthUpload },
    { key: "results", url: api.healthResults },
    { key: "zr", url: api.healthZR },
  ];

  for (const item of mappings) {
    const badge = document.querySelector(`[data-service="${item.key}"]`);
    if (!badge) {
      // Continue to the next mapping if the badge is missing.
      continue;
    }

    try {
      const resp = await fetchWithTimeout(item.url, {}, 5000);
      badge.textContent = resp.ok ? "ok" : "down";
      badge.classList.toggle("ok", resp.ok);
      badge.classList.toggle("fail", !resp.ok);
    } catch (err) {
      badge.textContent = "down";
      badge.classList.add("fail");
      badge.classList.remove("ok");
    }
  }
}

uploadBtn.addEventListener("click", uploadFile);
alertBtn.addEventListener("click", sendAlert);
refreshHealth.addEventListener("click", checkHealth);

checkHealth();
