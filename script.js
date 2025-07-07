// Api key from virustotal Api
const API_KEY =
  "21e43e29075e97c4439f73eaea655427959059953963ff135af518782dbb4fb9";

// Utility function to get DOM elements by ID
const getElement = (id) => document.getElementById(id);

// Actualizar el resultado de la pantalla que da el contenido
const updateResult = (content, display = true) => {
  const result = getElement("result");
  result.style.display = display ? "block" : "none";
  result.innerHTML = content;
};

// Shows a loading page spinner and message
const showLoading = (message) =>
  updateResult(`<div class="loading">
      <p>${message}</p>
      <div class="spinner"></div>
    </div>`);

// Corrige showError para aceptar mensaje
const showError = (message) => updateResult(`<p class="error">${message}</p>`);

// Generic function to make authenticated Api Request virusTotal
async function makeRequest(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: {
      "x-apikey": API_KEY,
      ...options.headers,
    },
  });

  //Handle failed requests
  if (!response.ok) {
    const error = await response
      .json()
      .catch(() => ({ error: response.statusText }));
    throw new Error(error.error || "Error en la solicitud");
  }

  return response.json();
}

// Polls VirusTotal for analysis result, retrying until complete or timeout
async function pollAnalysisResults(analysisId, fileName = "") {
  const maxAttempts = 20;
  let attempts = 0;
  let interval = 2000;

  while (attempts < maxAttempts) {
    try {
      showLoading(
        `Analizando${fileName ? ` ${fileName}` : ""}... (${(
          ((maxAttempts - attempts) * interval) /
          1000
        ).toFixed(0)} seconds remaining)`
      );

      const report = await makeRequest(
        `https://www.virustotal.com/api/v3/analyses/${analysisId}`
      );
      const status = report.data?.attributes?.status;

      if (!status) throw new Error("Análisis inválido");

      if (status === "completed") {
        showFormattwedResults(report);
        break;
      }

      if (status === "failed") {
        throw new Error("El análisis falló o no se completó.");
      }

      if (++attempts >= maxAttempts) {
        throw new Error(
          "Tiempo de espera agotado. Intente nuevamente más tarde."
        );
      }

      // Increase interval between retries
      interval = Math.min(interval * 1.5, 8000);
      await new Promise((resolve) => setTimeout(resolve, interval));
    } catch (error) {
      showError(`Error: ${error.message}`);
      break;
    }
  }
}

// Formats and displays the analysis results
function showFormattwedResults(data) {
  if (!data?.data?.attributes?.stats) {
    return showError("No se encontraron resultados de análisis.");
  }

  const stats = data.data.attributes.stats;
  const total = Object.values(stats).reduce((sum, value) => sum + value, 0);
  if (!total)
    return showError("Los Resultados de Los Analisis no están disponibles.");

  const getPercent = (val) => ((val / total) * 100).toFixed(1);

  const categories = {
    malicious: {
      color: "malicious",
      label: "Malicious",
    },
    suspicious: {
      color: "suspicious",
      label: "Suspicious",
    },
    harmless: {
      color: "harmless",
      label: "Harmless",
    },
    undetected: {
      color: "undetected",
      label: "Undetected",
    },
  };

  const percents = Object.keys(categories).reduce((acc, key) => {
    acc[key] = getPercent(stats[key] || 0);
    return acc;
  }, {});

  // Determine overall verdict
  const verdict =
    stats.malicious > 0
      ? "Malicious"
      : stats.suspicious > 0
      ? "Suspicious"
      : "safe";
  const verdictClass =
    stats.malicious > 0
      ? "malicious"
      : stats.suspicious > 0
      ? "suspicious"
      : "safe";

  // Render result summary UI
  updateResult(`
    <h3>Scan Report</h3>
    <div class="scan-stats">
      <p><strong>Verdict:</strong> <span class="${verdictClass}">${verdict}</span></p>
    <div class= "progress-section">
    <div class = "progress-label">
    <span>Resultados del Analisis </span>
    <span class= "progress-percent">${percents.malicious}% Detection Rate</span>
    </div>
    <div class="progress-stacked">
    ${Object.entries(categories)
      .map(
        ([key, { color, label }]) => `
    <div class="progress-bar ${color}" style="width: ${percents[key]}%"
     title="${categories[key].label} : ${stats[key]} (${percents[key]}%)">

    <span class="progress-label-overlay"> ${stats[key]} </span>

    </div>
  `
      )
      .join("")}
    </div>

    <div class="progress-legend">
    ${Object.entries(categories)
      .map(
        ([key, { color, label }]) => `
        <div class="legend-items">
          <span class="legend-color ${color}"></span>
          <span>${label} (${percents[key]}%)</span>
        </div>
      `
      )
      .join("")}
    </div>
    </div>

    <div class="detection-details">
      ${Object.entries(stats)
        .map(
          ([key, value]) =>
            `<div class="detail-item">${key}: ${value}
        <span class="detail-label">${key}</span>
        <span class="detail-value">${stats[key]}</span>
        <span class="detail-percent">${percents[key]}%</span>

        </div>`
        )
        .join("")}
      </div>
      <button onclick="showFullReport(this.getAttribute('data-report'))" data-report='${JSON.stringify(
        data
      )}'>View Full Report</button>
    `);

  //Trigger animation
  setTimeout(
    () =>
      getElement("result")
        .querySelector(".progress-stacked")
        .classList.add("animate"),
    1000
  );
}

// Display a detail report modal with engine-by-engine detection
function showFullReport(reportData) {
  const data =
    typeof reportData === "string" ? JSON.parse(reportData) : reportData;
  const modal = getElement("fullReportModal");
  const results = data.data?.attributes?.results;

  getElement("fullReportContent").innerHTML = `
 <h3>Full Details</h3>
 ${
   results
     ? `<table>
          <thead><tr><th>Engine</th><th>Result</th></tr></thead>
    
            ${Object.entries(results)
              .map(
                ([engine, { category }]) => `
            <tr>
              <td>${engine}</td>
              <td class="${
                category === "malicious"
                  ? "malicious"
                  : category === "suspicious"
                  ? "suspicious"
                  : "safe"
              }">${category}</td>
            </tr>
            `
              )
              .join("")}
        </table>`
     : "<p>No detailed results available!.</p>"
 }
 `;

  modal.style.display = "block";
  modal.offsetHeight;
  modal.classList.add("show");
}

// Close the full report modal
function closeModal() {
  const modal = getElement("fullReportModal");
  modal.classList.remove("show");
  setTimeout(() => {
    modal.style.display = "none";
  }, 300);
}

// Close modal on outside click
window.addEventListener("load", () => {
  const modal = getElement("fullReportModal");
  window.addEventListener("click", (e) => e.target === modal && closeModal());
});

// Handles the process of scanning a URL using VirusTotal
async function scanURL() {
  const url = getElement("urlInput").value.trim(); // Corrige el id aquí
  if (!url) return showError("Por favor, ingrese una URL.");

  try {
    new URL(url);
  } catch {
    return showError(
      "URL no válida. Por favor, ingrese una URL correcta. (ejemplo: https://www.example.com)"
    );
  }
  try {
    showLoading("Escaneando URL...");
    const encodeUrl = encodeURIComponent(url);

    // Submit Url to virusTotal for scanning
    const submitResult = await makeRequest(
      "https://www.virustotal.com/api/v3/urls",
      {
        method: "POST",
        headers: {
          accept: "application/json",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: `url=${encodeUrl}`,
      }
    );

    if (!submitResult.data || !submitResult.data.id) {
      throw new Error("Error al enviar la URL para escaneo.");
    }

    // Delay before polling for results
    await new Promise((resolve) => setTimeout(resolve, 3000));

    showLoading("Getting scan results...");
    await pollAnalysisResults(submitResult.data.id);
  } catch (error) {
    showError(`Error: ${error.message}`);
  }
}

// Handles the process of scanning a file using VirusTotal
async function scanFile() {
  const file = getElement("fileInput").files[0];
  if (!file)
    return showError("Por favor, seleccione un archivo para escanear.");
  if (file.size > 32 * 1024 * 1024) {
    return showError("El archivo es demasiado grande. Máximo 32 MB.");
  }

  try {
    showLoading("Escaneando archivo...");

    const formData = new FormData();
    formData.append("file", file);

    // Subir archivo a VirusTotal
    const uploadResult = await makeRequest(
      "https://www.virustotal.com/api/v3/files",
      {
        method: "POST",
        body: formData,
      }
    );

    if (!uploadResult.data || !uploadResult.data.id) {
      throw new Error("Error al enviar el archivo para escaneo.");
    }

    // Esperar un poco antes de empezar el polling
    await new Promise((resolve) => setTimeout(resolve, 2000));

    showLoading("Obteniendo resultados del análisis...");
    // Polling directo con el ID recibido
    await pollAnalysisResults(uploadResult.data.id, file.name);
  } catch (error) {
    showError(error.message || JSON.stringify(error));
  }
}

// Export functions to global scope for HTML onclick
window.scanURL = scanURL;
window.scanFile = scanFile;
window.showFullReport = showFullReport;
window.closeModal = closeModal;

// Handles the process of analyzing email content
async function analyzeEmailContent() {
  const emailContent = getElement("emailContentInput").value.trim();
  if (!emailContent) return showError("Por favor, pegue el contenido del correo electrónico.");

  showLoading("Analizando contenido del correo...");

  let analysisResultsHtml = "<h3>Resultados del Análisis de Correo</h3>";
  let scamDetected = false;

  // 1. Análisis de texto para palabras clave y patrones de estafa
  const scamKeywords = [
    "urgente", "verifique su cuenta", "acción requerida", "ganador", "premio",
    "herencia", "transferencia bancaria", "factura adjunta", "problema con su pago",
    "reembolso", "suspensión de cuenta", "actualice su información", "haga clic aquí",
    "descuento exclusivo", "oferta limitada", "confirmar datos", "seguridad de la cuenta"
  ];
  const suspiciousPatterns = [
    /urgente|inmediato/i, // Urgencia
    /ganador|premio|lotería/i, // Premios inesperados
    /verifique|actualice|confirme/i, // Solicitud de credenciales
    /factura|pago|transferencia/i, // Temas financieros
    /haga clic aquí|descargue|abra el archivo/i // Llamadas a la acción sospechosas
  ];

  let textAnalysisFindings = [];

  scamKeywords.forEach(keyword => {
    if (emailContent.toLowerCase().includes(keyword.toLowerCase())) {
      textAnalysisFindings.push(`Palabra clave sospechosa detectada: "${keyword}"`);
      scamDetected = true;
    }
  });

  suspiciousPatterns.forEach(pattern => {
    if (pattern.test(emailContent)) {
      textAnalysisFindings.push(`Patrón sospechoso detectado: "${pattern.source}"`);
      scamDetected = true;
    }
  });

  if (textAnalysisFindings.length > 0) {
    analysisResultsHtml += `<div class="text-analysis-section"><h4>Análisis de Texto:</h4>`;
    textAnalysisFindings.forEach(finding => {
      analysisResultsHtml += `<p class="${scamDetected ? 'malicious' : 'suspicious'}">${finding}</p>`;
    });
    analysisResultsHtml += `</div>`;
  } else {
    analysisResultsHtml += `<div class="text-analysis-section"><p class="safe">No se detectaron palabras clave o patrones de estafa obvios en el texto.</p></div>`;
  }

  // 2. Análisis de URLs
  const urlRegex = /(https?:\/\/[^\s"'<>()]+)/g;
  const urls = emailContent.match(urlRegex);

  if (urls && urls.length > 0) {
    analysisResultsHtml += `<h4>Análisis de Enlaces (${urls.length} encontrados):</h4>`;
    let linkAnalysisReports = [];
    for (const url of urls) {
      try {
        const encodeUrl = encodeURIComponent(url);
        const submitResult = await makeRequest(
          "https://www.virustotal.com/api/v3/urls",
          {
            method: "POST",
            headers: {
              accept: "application/json",
              "Content-Type": "application/x-www-form-urlencoded",
            },
            body: `url=${encodeUrl}`,
          }
        );

        if (submitResult.data && submitResult.data.id) {
          await new Promise((resolve) => setTimeout(resolve, 3000));
          const report = await pollAnalysisResults(submitResult.data.id);
          linkAnalysisReports.push({ url: url, report: report });
        } else {
          linkAnalysisReports.push({ url: url, error: "Error al enviar la URL." });
        }
      } catch (error) {
        linkAnalysisReports.push({ url: url, error: error.message });
      }
    }

    linkAnalysisReports.forEach(item => {
      analysisResultsHtml += `<div class="email-link-analysis">`;
      analysisResultsHtml += `<h5>URL: <a href="${item.url}" target="_blank">${item.url}</a></h5>`;
      if (item.report) {
        const stats = item.report.data?.attributes?.stats;
        if (stats) {
          const verdict = stats.malicious > 0 ? "Malicioso" : stats.suspicious > 0 ? "Sospechoso" : "Seguro";
          const verdictClass = stats.malicious > 0 ? "malicious" : stats.suspicious > 0 ? "suspicious" : "safe";
          analysisResultsHtml += `<p>Veredicto: <span class="${verdictClass}">${verdict}</span></p>`;
          analysisResultsHtml += `<p>Detecciones: Maliciosas: ${stats.malicious}, Sospechosas: ${stats.suspicious}, Inofensivas: ${stats.harmless}</p>`;
          if (stats.malicious > 0 || stats.suspicious > 0) {
            scamDetected = true;
          }
        } else {
          analysisResultsHtml += `<p>No se encontraron estadísticas de análisis.</p>`;
        }
      } else if (item.error) {
        analysisResultsHtml += `<p class="error">Error al analizar: ${item.error}</p>`;
      }
      analysisResultsHtml += `</div>`;
    });
  } else {
    analysisResultsHtml += `<p class="safe">No se encontraron URLs en el contenido del correo.</p>`;
  }

  // Resumen final
  if (scamDetected) {
    analysisResultsHtml = `<h3 class="malicious">¡Posible Estafa Detectada!</h3>` + analysisResultsHtml;
  } else if (textAnalysisFindings.length > 0) {
    analysisResultsHtml = `<h3 class="suspicious">Advertencia: Patrones Sospechosos</h3>` + analysisResultsHtml;
  } else {
    analysisResultsHtml = `<h3 class="safe">Análisis Completo: Parece Seguro</h3>` + analysisResultsHtml;
  }

  updateResult(analysisResultsHtml);
}

window.analyzeEmailContent = analyzeEmailContent;

// Close modal on outside click
window.addEventListener("load", () => {
  const modal = getElement("fullReportModal");
  window.addEventListener("click", (e) => e.target === modal && closeModal());
});
