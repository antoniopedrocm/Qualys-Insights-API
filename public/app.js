let charts = {};
let currentData = {
  vulnerabilities: [],
  filteredVulnerabilities: [],
  availableTags: [],
  hosts: [],
  filteredHosts: [],
  scans: [],
  effectiveness: null
};

// Configurações globais do Chart.js para o tema escuro
Chart.defaults.color = '#a0aec0';
Chart.defaults.borderColor = '#1a223a';
Chart.defaults.plugins.legend.position = 'bottom';
Chart.defaults.plugins.legend.labels.color = '#f0f4f8';

function showTab(tabName) {
  document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
  
  document.getElementById(tabName).classList.add('active');
  
  // Encontra o botão correspondente e o ativa
  const activeButton = document.querySelector(`.tab-btn[onclick="showTab('${tabName}')"]`);
  if (activeButton) {
    activeButton.classList.add('active');
  }

  // Atualiza o título da página
  const pageTitle = document.getElementById('pageTitle');
  const refreshButton = document.getElementById('refreshButton');
  
  if (tabName === 'dashboard') {
    pageTitle.textContent = 'Dashboard Executivo';
    refreshButton.style.display = 'block';
    refreshButton.onclick = loadDashboard;
  } else if (tabName === 'vulnerabilities') {
    pageTitle.textContent = 'Análise de Vulnerabilidades';
    refreshButton.style.display = 'block';
    refreshButton.onclick = loadVulnerabilities;
    if (currentData.vulnerabilities.length === 0) loadVulnerabilities(); // Carrega se vazio
  } else if (tabName === 'efetividade') {
    pageTitle.textContent = 'Efetividade';
    refreshButton.style.display = 'none';
  } else if (tabName === 'hosts') {
    pageTitle.textContent = 'Inventário de Hosts';
    refreshButton.style.display = 'block';
    refreshButton.onclick = loadHosts;
    if (currentData.hosts.length === 0) loadHosts(); // Carrega se vazio
  } else if (tabName === 'scans') {
    pageTitle.textContent = 'Status dos Scans';
    refreshButton.style.display = 'block';
    refreshButton.onclick = loadScans;
    if (currentData.scans.length === 0) loadScans(); // Carrega se vazio
  } else if (tabName === 'api') {
    pageTitle.textContent = 'API Explorer';
    refreshButton.style.display = 'none'; // Esconde o botão de refresh
  }
}

function showMessage(message, type = 'error') {
  const messagesDiv = document.getElementById('messages');
  const msgElement = document.createElement('div');
  msgElement.className = type;
  msgElement.textContent = message;
  messagesDiv.appendChild(msgElement);
  
  setTimeout(() => {
    msgElement.style.opacity = '0';
    setTimeout(() => messagesDiv.removeChild(msgElement), 300);
  }, 5000);
}

function showLoading(show) {
  document.getElementById('loadingIndicator').style.display = show ? 'block' : 'none';
}

function parseTags(tagString) {
  if (!tagString) return [];
  return tagString
    .split(/[,;|]/)
    .map(tag => tag.trim())
    .filter(Boolean);
}

function extractTagsFromVulns(vulnerabilities) {
  const tagSet = new Set();
  vulnerabilities.forEach(v => {
    parseTags(v.hostTags).forEach(tag => tagSet.add(tag));
  });
  return Array.from(tagSet).sort((a, b) => a.localeCompare(b, 'pt-BR', { sensitivity: 'base' }));
}

function populateTagFilter(tags) {
  const select = document.getElementById('tagFilter');
  if (!select) return;
  select.innerHTML = '<option value="">Todas as Tags</option>' +
    tags.map(tag => `<option value="${tag}">${tag}</option>`).join('');
}

async function apiCall(endpoint, needsAuth = true) {
  const headers = { 'Content-Type': 'application/json' };
  if (needsAuth) {
    // btoa (Base64) é uma função nativa do browser
    headers['Authorization'] = 'Basic ' + btoa('admin:admin123');
  }
  
  // O endpoint agora é relativo (o browser sabe que é no mesmo host)
  const response = await fetch(endpoint, { headers });
  if (!response.ok) {
    throw new Error(`Erro HTTP ${response.status} ao buscar ${endpoint}`);
  }
  return await response.json();
}

async function loadDashboard() {
  try {
    showLoading(true);
    
    // Otimização: chama os dois endpoints em paralelo
    const [summary, trends] = await Promise.all([
      apiCall('/api/dashboard/summary'),
      apiCall('/api/dashboard/trends')
    ]);

    if (!summary.success) throw new Error(summary.message);
    if (!trends.success) throw new Error(trends.message);

    // Preenche KPIs
    document.getElementById('totalHosts').textContent = summary.data.totalHosts;
    document.getElementById('totalVulns').textContent = summary.data.totalVulnerabilities;
    document.getElementById('criticalVulns').textContent = summary.data.severityDistribution.critical;
    document.getElementById('highVulns').textContent = summary.data.severityDistribution.high;
    document.getElementById('mediumVulns').textContent = summary.data.severityDistribution.medium;

    // Atualiza Gráficos
    updateCharts(summary.data, trends.data);

    showLoading(false);
    showMessage('Dashboard atualizado com sucesso!', 'success');
  } catch (error) {
    showLoading(false);
    showMessage('Erro ao carregar dashboard: ' + error.message, 'error');
  }
}

function updateCharts(summary, trends) {
  const sevColors = ['#e63946', '#f77f00', '#fbc02d']; // Crítico, Alto, Médio

  // --- Gráfico de Severidade (Doughnut) ---
  if (charts.severity) charts.severity.destroy();
  const severityCtx = document.getElementById('severityChart').getContext('2d');
  charts.severity = new Chart(severityCtx, {
    type: 'doughnut',
    data: {
      labels: ['Crítica', 'Alta', 'Média'],
      datasets: [{
        data: [
          summary.severityDistribution.critical,
          summary.severityDistribution.high,
          summary.severityDistribution.medium
        ],
        backgroundColor: sevColors,
        borderWidth: 0,
      }]
    },
    options: { 
      responsive: true, 
      maintainAspectRatio: false,
      plugins: { legend: { position: 'right' } } 
    }
  });

  // --- Gráfico Top 10 Vulnerabilidades (Bar) ---
  if (charts.topVulns) charts.topVulns.destroy();
  const topVulnsCtx = document.getElementById('topVulnsChart').getContext('2d');
  charts.topVulns = new Chart(topVulnsCtx, {
    type: 'bar',
    data: {
      labels: summary.topVulnerabilities.map(v => 'QID ' + v.qid),
      datasets: [{
        label: 'Ocorrências',
        data: summary.topVulnerabilities.map(v => v.count),
        backgroundColor: '#00aaff',
        borderRadius: 4,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      indexAxis: 'y', // Gráfico de barra horizontal para melhor leitura
      plugins: { legend: { display: false } },
      scales: { 
        x: { beginAtZero: true, grid: { color: '#1a223a' } },
        y: { grid: { display: false } }
      }
    }
  });

  const barChartOptions = (title) => ({
    responsive: true,
    maintainAspectRatio: true,
    plugins: { 
      legend: { display: false },
      title: { 
        display: true, 
        text: title,
        color: '#f0f4f8'
      }
    },
    scales: { 
      y: { beginAtZero: true, grid: { color: '#1a223a' } },
      x: { grid: { display: false } }
    }
  });

  // --- Gráfico Desenvolvimento e Qualidade (DEV_QA) ---
  if (charts.devQA) charts.devQA.destroy();
  const devQACtx = document.getElementById('devQAChart').getContext('2d');
  charts.devQA = new Chart(devQACtx, {
    type: 'bar',
    data: {
      labels: ['Crítica', 'Alta', 'Média'],
      datasets: [{
        label: 'Vulnerabilidades',
        data: [
          summary.tagDistribution?.DEV_QA?.critical || 0,
          summary.tagDistribution?.DEV_QA?.high || 0,
          summary.tagDistribution?.DEV_QA?.medium || 0
        ],
        backgroundColor: [sevColors[0], sevColors[1], sevColors[2]]
      }]
    },
    options: barChartOptions(`Total: ${(summary.tagDistribution?.DEV_QA?.total || 0)} vulnerabilidades`)
  });

  // --- Gráfico Produção Baixa (PRD_Baixa) ---
  if (charts.prdBaixa) charts.prdBaixa.destroy();
  const prdBaixaCtx = document.getElementById('prdBaixaChart').getContext('2d');
  charts.prdBaixa = new Chart(prdBaixaCtx, {
    type: 'bar',
    data: {
      labels: ['Crítica', 'Alta', 'Média'],
      datasets: [{
        label: 'Vulnerabilidades',
        data: [
          summary.tagDistribution?.PRD_Baixa?.critical || 0,
          summary.tagDistribution?.PRD_Baixa?.high || 0,
          summary.tagDistribution?.PRD_Baixa?.medium || 0
        ],
        backgroundColor: [sevColors[0], sevColors[1], sevColors[2]]
      }]
    },
    options: barChartOptions(`Total: ${(summary.tagDistribution?.PRD_Baixa?.total || 0)} vulnerabilidades`)
  });

  // --- Gráfico Produção Alta (PRD_Alta) ---
  if (charts.prdAlta) charts.prdAlta.destroy();
  const prdAltaCtx = document.getElementById('prdAltaChart').getContext('2d');
  charts.prdAlta = new Chart(prdAltaCtx, {
    type: 'bar',
    data: {
      labels: ['Crítica', 'Alta', 'Média'],
      datasets: [{
        label: 'Vulnerabilidades',
        data: [
          summary.tagDistribution?.PRD_Alta?.critical || 0,
          summary.tagDistribution?.PRD_Alta?.high || 0,
          summary.tagDistribution?.PRD_Alta?.medium || 0
        ],
        backgroundColor: [sevColors[0], sevColors[1], sevColors[2]]
      }]
    },
    options: barChartOptions(`Total: ${(summary.tagDistribution?.PRD_Alta?.total || 0)} vulnerabilidades`)
  });

  // --- Gráfico de Tendências (Line) ---
  if (charts.trends) charts.trends.destroy();
  const trendsCtx = document.getElementById('trendsChart').getContext('2d');
  charts.trends = new Chart(trendsCtx, {
    type: 'line',
    data: {
      labels: trends.trends.map(t => t.date),
      datasets: [{
        label: 'Vulnerabilidades Descobertas',
        data: trends.trends.map(t => t.count),
        borderColor: '#00f0e0', // Ciano
        backgroundColor: 'rgba(0, 240, 224, 0.1)',
        tension: 0.3,
        fill: true,
        pointRadius: 2,
        pointBackgroundColor: '#00f0e0',
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: { 
        y: { beginAtZero: true, grid: { color: '#1a223a' } },
        x: { grid: { display: false } }
      }
    }
  });
}

function classifyWindowFront(severity) {
  const sev = Number(severity) || 0;
  if (sev >= 4) return 'PRD_Alta';
  if (sev === 3) return 'PRD_Baixa';
  return 'DEV_QA';
}

function buildStackedChart(chartKey, canvasId, label, data) {
  if (charts[chartKey]) charts[chartKey].destroy();
  const ctx = document.getElementById(canvasId).getContext('2d');
  charts[chartKey] = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: [label],
      datasets: [
        {
          label: 'Corrigidas',
          data: [data.corrigidas],
          backgroundColor: '#2ecc71',
          stack: 'stack'
        },
        {
          label: 'Pendentes',
          data: [data.pendentes],
          backgroundColor: '#f1c40f',
          stack: 'stack'
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      scales: {
        x: { stacked: true, grid: { display: false } },
        y: { stacked: true, beginAtZero: true, grid: { color: '#1a223a' } }
      },
      plugins: {
        legend: { position: 'bottom' },
        title: {
          display: true,
          text: `Total: ${data.total}`,
          color: '#f0f4f8'
        }
      }
    }
  });
}

function populateEffectivenessTable(detections) {
  const tbody = document.getElementById('efetividadeTableBody');
  const severityLabel = { '5': 'Crítica', '4': 'Alta', '3': 'Média', '2': 'Baixa', '1': 'Info' };
  tbody.innerHTML = detections.map(det => {
    const windowName = classifyWindowFront(det.severity);
    return `
      <tr>
        <td>${det.detectionId || '-'}</td>
        <td>${det.status || '-'}</td>
        <td>${severityLabel[det.severity] || det.severity || '-'}</td>
        <td>${det.qid || '-'}</td>
        <td>${det.host || '-'}</td>
        <td>${det.lastFound ? det.lastFound.split('T')[0] : '-'}</td>
        <td>${windowName}</td>
      </tr>
    `;
  }).join('');
}

function renderEffectiveness(data) {
  currentData.effectiveness = data;

  const summary = {
    DEV_QA: data.DEV_QA || { total: 0, corrigidas: 0, pendentes: 0, efetividade: 0 },
    PRD_Baixa: data.PRD_Baixa || { total: 0, corrigidas: 0, pendentes: 0, efetividade: 0 },
    PRD_Alta: data.PRD_Alta || { total: 0, corrigidas: 0, pendentes: 0, efetividade: 0 }
  };

  document.getElementById('efetividadeKpis').style.display = 'grid';
  document.getElementById('efetividadeCharts').style.display = 'grid';
  document.getElementById('efetividadeTableWrapper').style.display = data.detections?.length ? 'block' : 'none';
  document.getElementById('efetividadeTotalLabel').style.display = 'block';

  document.getElementById('efetividadeTotal').textContent = data.total_geral || 0;
  document.getElementById('efetividadeTotalInline').textContent = data.total_geral || 0;
  document.getElementById('efetividadeDevQa').textContent = `${summary.DEV_QA.efetividade || 0}`;
  document.getElementById('efetividadePrdAlta').textContent = `${summary.PRD_Alta.efetividade || 0}`;
  document.getElementById('efetividadePrdBaixa').textContent = `${summary.PRD_Baixa.efetividade || 0}`;

  buildStackedChart('devQaEfetividade', 'devQaEfetividadeChart', 'DEV_QA', summary.DEV_QA);
  buildStackedChart('prdBaixaEfetividade', 'prdBaixaEfetividadeChart', 'PRD_Baixa', summary.PRD_Baixa);
  buildStackedChart('prdAltaEfetividade', 'prdAltaEfetividadeChart', 'PRD_Alta', summary.PRD_Alta);

  if (data.detections) {
    populateEffectivenessTable(data.detections);
  }
}

async function calculateEffectiveness() {
  try {
    showLoading(true);
    const response = await fetch('/efetividade/calcular', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Basic ' + btoa('admin:admin123')
      }
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(errorText || 'Erro ao calcular efetividade');
    }

    const data = await response.json();
    if (!data.success) {
      throw new Error(data.error || 'Erro ao calcular efetividade');
    }

    renderEffectiveness(data);
    showMessage('Efetividade calculada com sucesso!', 'success');
  } catch (error) {
    showMessage(error.message || 'Erro ao calcular efetividade', 'error');
  } finally {
    showLoading(false);
  }
}

async function loadVulnerabilities() {
  try {
    showLoading(true);
    const data = await apiCall('/api/vulnerabilities');
    currentData.vulnerabilities = data.data || [];
    currentData.filteredVulnerabilities = data.data || [];
    currentData.availableTags = extractTagsFromVulns(currentData.vulnerabilities);
    populateTagFilter(currentData.availableTags);
    displayVulnerabilities(currentData.vulnerabilities);
    document.getElementById('vulnTotal').textContent = currentData.vulnerabilities.length;
    showLoading(false);
    showMessage('Vulnerabilidades carregadas!', 'success');
  } catch (error) {
    showLoading(false);
    showMessage('Erro ao carregar vulnerabilidades: ' + error.message, 'error');
  }
}

function displayVulnerabilities(vulns) {
  const severityLabel = { '5': 'Crítica', '4': 'Alta', '3': 'Média', '2': 'Baixa', '1': 'Info' };
  const severityClass = { '5': 'critical', '4': 'high', '3': 'medium', '2': 'low', '1': 'low' };

  document.getElementById('vulnCount').textContent = vulns.length;
  document.getElementById('vulnTableBody').innerHTML = vulns.map(v => {
    // Prioriza uniqueVulnId, depois detectionId, senão vazio
    const detectionId = v.uniqueVulnId || v.detectionId || '';
    
    return `
    <tr>
      <td>${detectionId}</td>
      <td>${v.hostDns || ''}</td>
      <td>${v.hostIp || ''}</td>
      <td>${v.os || ''}</td>
      <td>${v.title || ''}</td>
      <td>${v.solution || ''}</td>
      <td>${v.results || ''}</td>
      <td class="severity-${severityClass[v.severity]}">${severityLabel[v.severity] || v.severity}</td>
      <td>${v.status || ''}</td>
      <td>${v.qid || ''}</td>
      <td>${v.port || ''}</td>
      <td>${v.firstFound ? v.firstFound.split('T')[0] : ''}</td>
    </tr>
  `;
  }).join('');
}

function applyFilters() {
  const selectedSeverities = Array.from(document.querySelectorAll('.severity-filter:checked'))
    .map(cb => cb.value);

  const quickSearch = document.getElementById('quickSearch').value.toLowerCase().trim();
  const quickSearchUpper = quickSearch.toUpperCase();
  const qid = document.getElementById('filterQid').value.trim();
  const selectedTag = document.getElementById('tagFilter').value;
  const status = document.getElementById('filterStatus').value;

  let filtered = currentData.vulnerabilities;

  const hasActiveFilters = selectedSeverities.length < 5 || quickSearch || qid || selectedTag || status;

  if (!hasActiveFilters) {
    currentData.filteredVulnerabilities = filtered;
    displayVulnerabilities(filtered);
    return;
  }

  // Filtro de severidade
  if (selectedSeverities.length > 0 && selectedSeverities.length < 5) {
    filtered = filtered.filter(v => selectedSeverities.includes(String(v.severity)));
  }
  // Busca rápida
  if (quickSearch) {
    filtered = filtered.filter(v => {
      const targets = [v.uniqueVulnId, v.detectionId, v.hostIp, v.hostDns, v.title, v.os, v.solution, v.status, v.port, v.qid];
      const hasTextMatch = targets.some(value => value && String(value).toLowerCase().includes(quickSearch));
      const hasResultMatch = v.results && String(v.results).toUpperCase().includes(quickSearchUpper);
      return hasTextMatch || hasResultMatch;
    });
  }
  // Filtro de QID
  if (qid) {
    filtered = filtered.filter(v => String(v.qid || '').includes(qid));
  }
  // Filtro de Tags cadastradas
  if (selectedTag) {
    filtered = filtered.filter(v => parseTags(v.hostTags).some(tag => tag.toLowerCase() === selectedTag.toLowerCase()));
  }
  // Filtro de Status
  if (status) {
    filtered = filtered.filter(v => v.status === status);
  }

  currentData.filteredVulnerabilities = filtered;
  displayVulnerabilities(filtered);
  
  if (filtered.length === 0) {
    showMessage('Nenhuma vulnerabilidade encontrada com os filtros aplicados.', 'error');
  }
}

function clearFilters() {
  document.querySelectorAll('.severity-filter').forEach(cb => cb.checked = true);
  document.getElementById('quickSearch').value = '';
  document.getElementById('filterQid').value = '';
  document.getElementById('tagFilter').value = '';
  document.getElementById('filterStatus').value = '';

  currentData.filteredVulnerabilities = currentData.vulnerabilities;
  displayVulnerabilities(currentData.vulnerabilities);
  
  showMessage('Filtros limpos!', 'success');
}

async function exportFiltered() {
  try {
    if (!currentData.filteredVulnerabilities || currentData.filteredVulnerabilities.length === 0) {
      showMessage('Nenhuma vulnerabilidade para exportar!', 'error');
      return;
    }
    const headers = ['Detection ID', 'DNS', 'Host IP', 'Sistema Operacional', 'Título', 'Solução', 'Resultados', 'Severidade', 'Status', 'QID', 'Porta', 'Primeira Detecção'];
    const severityLabel = { '5': 'Crítica', '4': 'Alta', '3': 'Média', '2': 'Baixa', '1': 'Info' };
    
    let csv = headers.join(',') + '\n';
    
    currentData.filteredVulnerabilities.forEach(vuln => {
      const row = [
        vuln.uniqueVulnId || vuln.detectionId,
        vuln.hostDns,
        vuln.hostIp,
        vuln.os || '',
        vuln.title || '',
        vuln.solution || '',
        vuln.results || '',
        severityLabel[vuln.severity] || vuln.severity,
        vuln.status,
        vuln.qid,
        vuln.port,
        vuln.firstFound
      ].map(field => `"${String(field || '').replace(/"/g, '""')}"`); // Escapa aspas
      
      csv += row.join(',') + '\n';
    });

    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `qualys_filtered_${new Date().toISOString().slice(0,10)}.csv`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
    
    showMessage(`${currentData.filteredVulnerabilities.length} vulnerabilidades exportadas!`, 'success');
  } catch (error) {
    showMessage('Erro ao exportar: ' + error.message, 'error');
  }
}

async function loadHosts() {
  try {
    showLoading(true);
    // Chama ambas as APIs em paralelo
    const [hostsData, vulnsData] = await Promise.all([
      apiCall('/api/hosts'),
      apiCall('/api/vulnerabilities')
    ]);
    
    // Calcula vulnerabilidades (C/A/M) por host (lógica do lado do cliente)
    const vulnsByHost = {};
    (vulnsData.data || []).forEach(vuln => {
      if (['3', '4', '5'].includes(vuln.severity)) {
        const ip = vuln.hostIp;
        vulnsByHost[ip] = (vulnsByHost[ip] || 0) + 1;
      }
    });
    
    currentData.hosts = (hostsData.data || []).map(host => ({
      ...host,
      vulnCount: vulnsByHost[host.ip] || 0
    }));
    
    currentData.filteredHosts = currentData.hosts;
    displayHosts(currentData.hosts);
    
    document.getElementById('hostTotal').textContent = hostsData.total || 0;
    showLoading(false);
    showMessage('Hosts carregados com sucesso!', 'success');
  } catch (error) {
    showLoading(false);
    showMessage('Erro ao carregar hosts: ' + error.message, 'error');
  }
}

function displayHosts(hosts) {
  document.getElementById('hostCount').textContent = hosts.length;
  document.getElementById('hostTableBody').innerHTML = hosts.map(h => {
    let vulnClass = 'low';
    if (h.vulnCount > 10) vulnClass = 'critical';
    else if (h.vulnCount > 5) vulnClass = 'high';
    
    return `
      <tr>
        <td>${h.id}</td>
        <td>${h.ip}</td>
        <td>${h.dns || '-'}</td>
        <td>${h.netbios || '-'}</td>
        <td>${h.tags || '-'}</td>
        <td style="text-align: center;">
          <span class="vuln-count-badge severity-${vulnClass}" 
                style="background-color: var(--sev-${vulnClass})">
            ${h.vulnCount}
          </span>
        </td>
        <td>${h.os || '-'}</td>
        <td>${h.lastVulnScan || '-'}</td>
      </tr>
    `;
  }).join('');
}

function filterHosts() {
  const search = document.getElementById('searchHost').value.toLowerCase().trim();
  
  if (!search) {
    currentData.filteredHosts = currentData.hosts;
    displayHosts(currentData.hosts);
    return;
  }
  
  const filtered = currentData.hosts.filter(h => 
    h.ip.toLowerCase().includes(search) ||
    (h.dns && h.dns.toLowerCase().includes(search)) ||
    (h.netbios && h.netbios.toLowerCase().includes(search)) ||
    (h.tags && h.tags.toLowerCase().includes(search)) ||
    (h.id && h.id.toString().includes(search))
  );
  
  currentData.filteredHosts = filtered;
  displayHosts(filtered);
}

function clearHostSearch() {
  document.getElementById('searchHost').value = '';
  currentData.filteredHosts = currentData.hosts;
  displayHosts(currentData.hosts);
  showMessage('Busca limpa!', 'success');
}

async function exportHosts() {
  try {
    if (!currentData.filteredHosts || currentData.filteredHosts.length === 0) {
      showMessage('Nenhum host para exportar!', 'error');
      return;
    }
    const headers = ['ID', 'IP', 'DNS', 'NetBIOS', 'Tags', 'N° Vulnerabilidades (C/A/M)', 'Sistema Operacional', 'Último Scan'];
    let csv = headers.join(',') + '\n';
    
    currentData.filteredHosts.forEach(host => {
      const row = [
        host.id,
        host.ip,
        host.dns,
        host.netbios,
        host.tags || '',
        host.vulnCount || 0,
        host.os,
        host.lastVulnScan
      ].map(field => `"${String(field || '').replace(/"/g, '""')}"`);
      csv += row.join(',') + '\n';
    });

    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `qualys_hosts_${new Date().toISOString().slice(0,10)}.csv`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
    
    showMessage(`${currentData.filteredHosts.length} hosts exportados!`, 'success');
  } catch (error) {
    showMessage('Erro ao exportar hosts: ' + error.message, 'error');
  }
}

async function loadScans() {
  try {
    showLoading(true);
    const data = await apiCall('/api/scans');
    currentData.scans = data.data || [];
    
    document.getElementById('scanCount').textContent = data.total || 0;
    document.getElementById('scanTableBody').innerHTML = (data.data || []).map(s => `
      <tr>
        <td>${s.ref || ''}</td>
        <td>${s.title || ''}</td>
        <td>${s.type || ''}</td>
        <td>${s.launchDate || ''}</td>
        <td>${s.state || ''}</td>
        <td>${s.target || ''}</td>
      </tr>
    `).join('');
    
    showLoading(false);
    showMessage('Scans carregados!', 'success');
  } catch (error) {
    showLoading(false);
    showMessage('Erro ao carregar scans: ' + error.message, 'error');
  }
}

async function testApiEndpoint() {
  const apiResponse = document.getElementById('apiResponse');
  try {
    const endpoint = document.getElementById('apiEndpoint').value;
    const needsAuth = endpoint !== '/api/health';
    
    apiResponse.textContent = `Executando ${endpoint}...`;
    const data = await apiCall(endpoint, needsAuth);
    
    apiResponse.textContent = JSON.stringify(data, null, 2);
    showMessage('Endpoint executado com sucesso!', 'success');
  } catch (error) {
    apiResponse.textContent = 'Erro: ' + error.message;
    showMessage('Erro ao executar endpoint: ' + error.message, 'error');
  }
}

async function exportExcel() {
  try {
    const response = await fetch('/api/export/vulnerabilities/excel', {
      headers: { 'Authorization': 'Basic ' + btoa('admin:admin123') }
    });
    
    if (!response.ok) throw new Error(`Erro ${response.status} ao exportar Excel`);
    
    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'qualys_vulnerabilities.xlsx';
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
    
    showMessage('Excel exportado com sucesso!', 'success');
  } catch (error) {
    showMessage('Erro ao exportar Excel: ' + error.message, 'error');
  }
}

async function exportCSV() {
  try {
    const response = await fetch('/api/export/vulnerabilities/csv', {
      headers: { 'Authorization': 'Basic ' + btoa('admin:admin123') }
    });
    
    if (!response.ok) throw new Error(`Erro ${response.status} ao exportar CSV`);
    
    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'qualys_vulnerabilities.csv';
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
    
    showMessage('CSV exportado com sucesso!', 'success');
  } catch (error) {
    showMessage('Erro ao exportar CSV: ' + error.message, 'error');
  }
}

// Carregar dashboard ao iniciar
window.onload = () => {
  loadDashboard();
};