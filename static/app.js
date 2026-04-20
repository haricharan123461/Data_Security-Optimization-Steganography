const socket = io();

const roomInput = document.getElementById("room");
const usernameInput = document.getElementById("username");
const receiverInput = document.getElementById("receiver");
const messageInput = document.getElementById("message");
const imageInput = document.getElementById("imageInput");
const joinBtn = document.getElementById("joinBtn");
const sendBtn = document.getElementById("sendBtn");
const sendImageBtn = document.getElementById("sendImageBtn");
const presenceEl = document.getElementById("presence");
const feedEl = document.getElementById("feed");
const bestSummaryEl = document.getElementById("bestSummary");
const transitPacketEl = document.getElementById("transitPacket");
const stagesEl = document.getElementById("stages");
const candidatesEl = document.getElementById("candidates");
const complianceTraceEl = document.getElementById("complianceTrace");
const sizeChartCtx = document.getElementById("sizeChart");
const scoreChartCtx = document.getElementById("scoreChart");
const shareChartCtx = document.getElementById("shareChart");

let sizeChart;
let scoreChart;
let shareChart;

function renderSizeChart(sizeProfile) {
  const labels = ["Input", "Encrypted", "Binary(eq)", "DNA", "RNA"];
  const values = [
    sizeProfile.input_bytes,
    sizeProfile.encrypted_bytes,
    sizeProfile.binary_bytes_equivalent,
    sizeProfile.dna_text_bytes,
    sizeProfile.rna_text_bytes,
  ];

  if (sizeChart) {
    sizeChart.destroy();
  }

  sizeChart = new Chart(sizeChartCtx, {
    type: "bar",
    data: {
      labels,
      datasets: [{
        label: "Size (bytes)",
        data: values,
        backgroundColor: ["#4f7cff", "#7d5bff", "#4bc0c0", "#ff9f40", "#ffcd56"],
      }],
    },
    options: {
      responsive: true,
      plugins: { legend: { display: false } },
      scales: { y: { beginAtZero: true } },
    },
  });
}

function renderScoreChart(scoreProfile) {
  const labels = scoreProfile.map((item) => item.name);
  const values = scoreProfile.map((item) => item.score);

  if (scoreChart) {
    scoreChart.destroy();
  }

  scoreChart = new Chart(scoreChartCtx, {
    type: "line",
    data: {
      labels,
      datasets: [{
        label: "Encryption Score",
        data: values,
        fill: false,
        borderColor: "#49dcb1",
        tension: 0.25,
      }],
    },
    options: {
      responsive: true,
      scales: { y: { beginAtZero: true, max: 1 } },
    },
  });
}

function renderShareChart(sizeProfile) {
  if (shareChart) {
    shareChart.destroy();
  }

  shareChart = new Chart(shareChartCtx, {
    type: "pie",
    data: {
      labels: ["Input", "Encrypted", "DNA"],
      datasets: [{
        data: [
          sizeProfile.input_bytes,
          sizeProfile.encrypted_bytes,
          sizeProfile.dna_text_bytes,
        ],
        backgroundColor: ["#4f7cff", "#7d5bff", "#ff9f40"],
      }],
    },
    options: { responsive: true },
  });
}

joinBtn.addEventListener("click", () => {
  socket.emit("join", {
    room: roomInput.value.trim(),
    username: usernameInput.value.trim(),
  });
});

sendBtn.addEventListener("click", () => {
  const plaintext = messageInput.value.trim();
  if (!plaintext) {
    return;
  }

  socket.emit("secure_message", {
    room: roomInput.value.trim(),
    sender: usernameInput.value.trim(),
    receiver: receiverInput.value.trim(),
    plaintext,
  });

  messageInput.value = "";
});

sendImageBtn.addEventListener("click", () => {
  const file = imageInput.files[0];
  if (!file) {
    alert("Please choose an image first.");
    return;
  }

  const reader = new FileReader();
  reader.onload = () => {
    socket.emit("secure_image", {
      room: roomInput.value.trim(),
      sender: usernameInput.value.trim(),
      receiver: receiverInput.value.trim(),
      file_name: file.name,
      image_data: reader.result,
    });
  };
  reader.readAsDataURL(file);
});

socket.on("presence", (payload) => {
  presenceEl.textContent = `Room: ${payload.room} | Members: ${payload.members.join(", ")}`;
});

socket.on("error_message", (payload) => {
  alert(payload.message);
});

socket.on("secure_message_result", (payload) => {
  const item = document.createElement("li");
  if (payload.payload_kind === "image") {
    item.innerHTML = `
      <strong>${payload.sender}</strong> ➜ <strong>${payload.receiver}</strong> (Image)<br/>
      File: ${payload.file_name} | Size: ${payload.original_size} bytes<br/>
      Cipher Preview: <code>${payload.cipher_preview}</code><br/>
      <img class="shared-image" src="${payload.decrypted_image_data}" alt="Decrypted shared image" />
    `;
  } else {
    item.innerHTML = `
      <strong>${payload.sender}</strong> ➜ <strong>${payload.receiver}</strong><br/>
      Plain: ${payload.plaintext}<br/>
      Cipher Preview: <code>${payload.cipher_preview}</code><br/>
      Decrypted: ${payload.decrypted_text}
    `;
  }
  feedEl.prepend(item);

  bestSummaryEl.innerHTML = `
    <strong>Best Method:</strong> ${payload.best_method}<br/>
    <strong>Score:</strong> ${payload.best_score}<br/>
    <strong>Optimization Methods:</strong> ${payload.optimization_methods.join(" + ")}<br/>
    <strong>Methods Evaluated:</strong> ${payload.methods_evaluated}<br/>
    <strong>Comet Generations:</strong> ${payload.comet_generations}<br/>
    <strong>Encryption Growth:</strong> ${payload.size_profile.encryption_growth_ratio}x<br/>
    <strong>DNA/Binary Ratio:</strong> ${payload.size_profile.dna_vs_binary_ratio}x<br/>
    <strong>GC Ratio:</strong> ${payload.metrics.gc_ratio}<br/>
    <strong>Homopolymer Run:</strong> ${payload.metrics.max_homopolymer}<br/>
    <strong>Elapsed:</strong> ${payload.metrics.elapsed_ms} ms
  `;

  transitPacketEl.innerHTML = `
    <strong>Packet Kind:</strong> ${payload.transit_packet.kind}<br/>
    <strong>Encrypted Size:</strong> ${payload.transit_packet.encrypted_size} bytes<br/>
    <strong>SHA-256:</strong> <code>${payload.transit_packet.encrypted_sha256}</code><br/>
    <strong>Encrypted Payload (Base64 preview):</strong><br/>
    <code>${payload.transit_packet.encrypted_payload_preview_b64}</code>
  `;

  complianceTraceEl.innerHTML = "";
  payload.compliance_trace.forEach((entry) => {
    const li = document.createElement("li");
    li.innerHTML = `<strong>${entry.equation}:</strong> ${entry.description}`;
    complianceTraceEl.appendChild(li);
  });

  renderSizeChart(payload.size_profile);
  renderScoreChart(payload.score_profile);
  renderShareChart(payload.size_profile);

  stagesEl.innerHTML = "";
  payload.stage_trace.forEach((stage) => {
    const li = document.createElement("li");
    li.textContent = `${stage.stage} | ${stage.method} | ${stage.output}`;
    stagesEl.appendChild(li);
  });

  candidatesEl.innerHTML = "";
  payload.candidate_table.forEach((candidate) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${candidate.name}</td>
      <td>${candidate.optimization_method}</td>
      <td>${candidate.score}</td>
      <td>${candidate.gc_ratio}</td>
      <td>${candidate.max_homopolymer}</td>
      <td>${candidate.elapsed_ms}</td>
    `;
    candidatesEl.appendChild(tr);
  });
});
