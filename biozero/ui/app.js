// SPDX-License-Identifier: AGPL-3.0-only
const uploadBtn = document.getElementById("uploadBtn");
const alertBtn = document.getElementById("alertBtn");
const refreshHealth = document.getElementById("refreshHealth");
const uploadStatus = document.getElementById("uploadStatus");
const resultsBox = document.getElementById("resultsBox");
const jobMeta = document.getElementById("jobMeta");
const alertBox = document.getElementById("alertBox");

const api = {
  upload: "/api/upload",
  results: "/api/results",
  alert: "/api/alert",
  healthUpload: "/api/health/upload",
  healthResults: "/api/health/results",
  healthZR: "/api/health/zeroresponder",
};

async function hashFile(file) {
  const buf = await file.arrayBuffer();
  const hash = await crypto.subtle.digest("SHA-256", buf);
  const bytes = Array.from(new Uint8Array(hash));
  return bytes.map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function uploadFile() {
  const fileInput = document.getElementById("fileInput");
  const clientId = document.getElementById("clientId").value.trim();
  const file = fileInput.files[0];

  if (!clientId) {
    uploadStatus.textContent = "Client ID is required.";
    return;
  }
  if (!file) {
    uploadStatus.textContent = "Select a FASTQ file.";
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
    const resp = await fetch(api.upload, {
      method: "POST",
      headers: {
        "X-Content-SHA256": hash,
        "X-Client-Id": clientId,
      },
      body: form,
    });

    if (!resp.ok) {
      const text = await resp.text();
      uploadStatus.textContent = `Upload failed: ${text}`;
      uploadBtn.disabled = false;
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
    uploadBtn.disabled = false;
  }
}

async function pollResults(jobId, clientId) {
  const url = `${api.results}/${jobId}`;
  for (let i = 0; i < 30; i += 1) {
    const resp = await fetch(url, {
      headers: {
        "X-Client-Id": clientId,
      },
    });

    if (!resp.ok) {
      resultsBox.textContent = `Error: ${await resp.text()}`;
      return;
    }

    const data = await resp.json();
    if (data.status === "processed") {
      resultsBox.textContent = JSON.stringify(data, null, 2);
      uploadStatus.textContent = "Results ready.";
      return;
    }

    uploadStatus.textContent = "Processing...";
    await new Promise((r) => setTimeout(r, 2000));
  }

  uploadStatus.textContent = "Timed out waiting for results.";
}

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
    const resp = await fetch(api.alert, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    const data = await resp.json();
    alertBox.textContent = JSON.stringify(data, null, 2);
  } catch (err) {
    alertBox.textContent = `Error: ${err.message}`;
  } finally {
    alertBtn.disabled = false;
  }
}

async function checkHealth() {
  const mappings = [
    { key: "upload", url: api.healthUpload },
    { key: "results", url: api.healthResults },
    { key: "zr", url: api.healthZR },
  ];

  for (const item of mappings) {
    const badge = document.querySelector(`[data-service="${item.key}"]`);
    if (!badge) continue;

    try {
      const resp = await fetch(item.url);
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
