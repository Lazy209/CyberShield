const CyberShield = {
  renderResults(data, container) {
    container.classList.remove('hidden');
    const risk = data.risk_level || 'low';
    const summary = data.summary || 'Scan complete';
    const scanId = data.scan_id;

    let html = `
      <div class="result-header">
        <div class="result-summary">${summary}</div>
        <span class="risk-badge risk-${risk}">${risk}</span>
      </div>`;

    if (data.score !== undefined) html += `<p>Score: <strong>${data.score}/100</strong> — ${data.strength || ''}</p>`;
    if (data.phishing_score !== undefined) html += `<p>Phishing Score: <strong>${data.phishing_score}/100</strong></p>`;
    if (data.security_score !== undefined) html += `<p>Security Score: <strong>${data.security_score}/100</strong></p>`;
    if (data.hashes) {
      html += `<p><strong>MD5:</strong> <code>${data.hashes.md5}</code></p>`;
      html += `<p><strong>SHA256:</strong> <code>${data.hashes.sha256}</code></p>`;
    }
    if (data.suggestions && data.suggestions.length) {
      html += '<h3>Suggestions</h3><ul>' + data.suggestions.map(s => `<li>${s}</li>`).join('') + '</ul>';
    }
    if (data.checks) {
      html += '<h3>Checks</h3>';
      data.checks.forEach(c => {
        html += `<div class="finding severity-${c.passed ? 'low' : 'high'}"><strong>${c.name}</strong>${c.detail}</div>`;
      });
    }
    if (data.findings) {
      html += '<h3>Findings</h3>';
      data.findings.forEach(f => {
        html += `<div class="finding severity-${f.severity || 'info'}"><strong>${f.title}</strong>${f.detail}</div>`;
      });
    }
    if (scanId) {
      html += `<p style="margin-top:16px"><a href="/api/report/${scanId}" class="btn btn-sm">Download PDF Report</a></p>`;
    }
    container.innerHTML = html;
  }
};

document.querySelectorAll('#scan-form[data-endpoint]').forEach(form => {
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const endpoint = form.dataset.endpoint;
    const input = form.querySelector('#scan-input');
    const fd = new FormData(form);
    const container = document.getElementById('scan-results');
    container.classList.remove('hidden');
    container.innerHTML = '<p>Scanning...</p>';
    try {
      const res = await fetch(endpoint, { method: 'POST', body: fd });
      const data = await res.json();
      CyberShield.renderResults(data, container);
    } catch (err) {
      container.innerHTML = '<p class="alert alert-error">Scan failed. Please try again.</p>';
    }
  });
});
