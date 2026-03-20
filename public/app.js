let charts = {};
const DEFAULT_STATUS_ORDER = ['New', 'Active', 'Re-Opened', 'Fixed'];
let selectedStatuses = [];
let currentData = {
  vulnerabilities: [],
  filteredVulnerabilities: [],
  availableTags: [],
  hosts: [],
  filteredHosts: [],
  scans: [],
  effectiveness: null
};

const EFFECTIVENESS_WINDOW_LABELS = {
  DEV_QA: 'Desenvolvimento e Qualidade',
  PRD_Baixa: 'Produção Baixa',
  PRD_Alta: 'Produção Alta'
};

const EFFECTIVENESS_WINDOW_TAG_MATCHERS = {
  DEV_QA: ['DEV_QA', 'DESENVOLVIMENTO_E_QUALIDADE', 'DESENVOLVIMENTO', 'QUALIDADE'],
  PRD_Baixa: ['PRD_BAIXA', 'PRODUCAO_BAIXA', 'PRODUÇÃO_BAIXA'],
  PRD_Alta: ['PRD_ALTA', 'PRODUCAO_ALTA', 'PRODUÇÃO_ALTA']
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

  const activeButton = document.querySelector(`.tab-btn[onclick="showTab('${tabName}')"]`);
  if (activeButton) {
    activeButton.classList.add('active');
  }

  const pageTitle = document.getElementById('pageTitle');
  const refreshButton = document.getElementById('refreshButton');

  if (tabName === 'dashboard') {
    pageTitle.textContent = 'Dashboard Executivo';
    refreshButton.style.display = 'block';
    refreshButton.onclick = loadDashboard;
    syncDashboardViewControls();
  } else if (tabName === 'vulnerabilities') {
    pageTitle.textContent = 'Análise de Vulnerabilidades';
    refreshButton.style.display = 'block';
    refreshButton.onclick = loadVulnerabilities;
    if (currentData.vulnerabilities.length === 0) loadVulnerabilities();
  } else if (tabName === 'efetividade') {
    pageTitle.textContent = 'Efetividade';
    refreshButton.style.display = 'none';
    if (!currentData.effectiveness) clearEffectivenessView();
  } else if (tabName === 'hosts') {
    pageTitle.textContent = 'Inventário de Hosts';
    refreshButton.style.display = 'block';
    refreshButton.onclick = loadHosts;
    if (currentData.hosts.length === 0) loadHosts();
  } else if (tabName === 'scans') {
    pageTitle.textContent = 'Status dos Scans';
    refreshButton.style.display = 'block';
    refreshButton.onclick = loadScans;
    if (currentData.scans.length === 0) loadScans();
  } else if (tabName === 'api') {
    pageTitle.textContent = 'API Explorer';
    refreshButton.style.display = 'none';
  }

  if (tabName !== 'dashboard') {
    const selector = document.getElementById('dashboardViewSelector');
    if (selector) selector.style.display = 'none';
    const dateFilter = document.getElementById('dashboardDateFilter');
    if (dateFilter) dateFilter.style.display = 'none';
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

function isQueuedResponse(response) {
  if (!response || typeof response !== 'object') return false;
  const hasQueueHints = response.retryAfterSeconds !== undefined || response.callsToFinish !== undefined || response.queued;
  return response.success === false && hasQueueHints;
}

function buildQueueMessage(response) {
  const retrySeconds = Number.isFinite(Number(response?.retryAfterSeconds))
    ? Math.max(1, Math.round(Number(response.retryAfterSeconds)))
    : null;
  const retryText = retrySeconds
    ? `Consulta em processamento, tente novamente em ${retrySeconds} segundos.`
    : 'Consulta em processamento, tente novamente em breve.';
  const cacheText = response?.data ? ' Exibindo dados em cache enquanto aguardamos a finalização.' : '';
  return `${retryText}${cacheText}`;
}

function handleQueueResponse(response) {
  if (!isQueuedResponse(response)) return false;
  showMessage(buildQueueMessage(response), 'warning');
  return true;
}

function normalizeWindowTags(tags = '') {
  return String(tags)
    .toUpperCase()
    .replace(/\s+/g, '_')
    .replace(/\//g, '_');
}

function findWindowByTags(tags = '') {
  const normalized = normalizeWindowTags(tags);
  return Object.keys(EFFECTIVENESS_WINDOW_TAG_MATCHERS).find(windowKey =>
    EFFECTIVENESS_WINDOW_TAG_MATCHERS[windowKey].some(tag => normalized.includes(tag))
  );
}

function getOfficialDetectionId(vuln) {
  return vuln.detectionId || vuln.uniqueVulnId || '';
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

function getAvailableStatuses(vulnerabilities = []) {
  const discovered = new Set((vulnerabilities || []).map((item) => item?.status).filter(Boolean));
  const ordered = DEFAULT_STATUS_ORDER.filter((status) => discovered.has(status));
  const extras = Array.from(discovered)
    .filter((status) => !DEFAULT_STATUS_ORDER.includes(status))
    .sort((a, b) => a.localeCompare(b, 'en', { sensitivity: 'base' }));
  return [...ordered, ...extras];
}

function getStatusLabel(status) {
  if (status === 'New') return 'Novo';
  if (status === 'Active') return 'Ativo';
  if (status === 'Re-Opened') return 'Reaberto';
  if (status === 'Fixed') return 'Corrigido';
  return status;
}

function updateStatusFilterLabel() {
  const label = document.getElementById('statusFilterLabel');
  if (!label) return;

  const totalStatuses = getAvailableStatuses(currentData.vulnerabilities).length;
  if (selectedStatuses.length === 0 || (totalStatuses > 0 && selectedStatuses.length === totalStatuses)) {
    label.textContent = 'Todos os Status';
    return;
  }

  label.textContent = `Selecionados (${selectedStatuses.length})`;
}

function renderStatusFilterOptions() {
  const container = document.getElementById('statusFilterOptions');
  if (!container) return;

  const statuses = getAvailableStatuses(currentData.vulnerabilities);
  container.innerHTML = statuses.map((status) => `
    <label class="status-filter-option">
      <input type="checkbox" value="${status}" ${selectedStatuses.includes(status) ? 'checked' : ''} onchange="toggleStatusSelection(this.value)">
      <span>${getStatusLabel(status)}</span>
    </label>
  `).join('');

  updateStatusFilterLabel();
}

function toggleStatusDropdown(forceState) {
  const dropdown = document.getElementById('statusFilterDropdown');
  const trigger = document.getElementById('statusFilterTrigger');
  if (!dropdown || !trigger) return;

  const nextOpenState = typeof forceState === 'boolean' ? forceState : !dropdown.classList.contains('open');
  dropdown.classList.toggle('open', nextOpenState);
  trigger.setAttribute('aria-expanded', String(nextOpenState));
}

function toggleStatusSelection(status) {
  if (selectedStatuses.includes(status)) {
    selectedStatuses = selectedStatuses.filter((item) => item !== status);
  } else {
    selectedStatuses = [...selectedStatuses, status];
  }

  renderStatusFilterOptions();
  applyFilters();
}

async function apiCall(endpoint, needsAuth = true) {
  const headers = { 'Content-Type': 'application/json' };
  if (needsAuth) {
    // btoa (Base64) é uma função nativa do browser
    headers['Authorization'] = 'Basic ' + btoa('admin:admin123');
  }

  // O endpoint agora é relativo (o browser sabe que é no mesmo host)
  const response = await fetch(endpoint, { headers });
  const rawText = await response.text();

  let parsedBody = null;
  try {
    parsedBody = rawText ? JSON.parse(rawText) : null;
  } catch (parseError) {
    parsedBody = rawText;
  }

  const isQueued = response.status === 503 && parsedBody?.success === false;
  if (isQueued) {
    return { ...parsedBody, queued: true, status: response.status };
  }

  if (!response.ok) {
    const serverMessage = parsedBody?.message || parsedBody?.error;
    const message = serverMessage ? `${serverMessage} (HTTP ${response.status})` : `Erro HTTP ${response.status} ao buscar ${endpoint}`;
    throw new Error(message);
  }

  return parsedBody;
}

const dashboardState = {
  selectedView: 'geral',
  dateFilterMode: 'detection',
  startDate: '',
  endDate: '',
  fixStartDate: '',
  fixEndDate: '',
  vulnerabilities: []
};

function normalizeDateRange(start, end) {
  const today = new Date();
  today.setHours(0, 0, 0, 0);

  const defaultStart = new Date(today);
  defaultStart.setDate(defaultStart.getDate() - 30);

  const normalizedEnd = end ? new Date(`${end}T00:00:00`) : today;
  const normalizedStart = start ? new Date(`${start}T00:00:00`) : defaultStart;

  if (Number.isNaN(normalizedStart.getTime()) || Number.isNaN(normalizedEnd.getTime())) {
    throw new Error('Informe datas válidas para o período.');
  }

  if (normalizedStart > normalizedEnd) {
    throw new Error('Data inicial não pode ser maior que data final.');
  }

  return {
    startDate: normalizedStart.toISOString().split('T')[0],
    endDate: normalizedEnd.toISOString().split('T')[0]
  };
}

function getDetectedAt(vuln) {
  return vuln.detectedAt || (vuln.firstFound ? String(vuln.firstFound).split('T')[0] : '');
}

function normalizeDateToYmd(value) {
  if (!value) return '';

  if (value instanceof Date && !Number.isNaN(value.getTime())) {
    return value.toISOString().split('T')[0];
  }

  if (typeof value === 'number' && Number.isFinite(value)) {
    const fromNumber = new Date(value);
    return Number.isNaN(fromNumber.getTime()) ? '' : fromNumber.toISOString().split('T')[0];
  }

  const raw = String(value).trim();
  if (!raw) return '';

  const ddMmYyyy = raw.match(/^(\d{2})\/(\d{2})\/(\d{4})$/);
  if (ddMmYyyy) {
    const [, day, month, year] = ddMmYyyy;
    return `${year}-${month}-${day}`;
  }

  const isoLike = raw.match(/^(\d{4}-\d{2}-\d{2})/);
  if (isoLike) return isoLike[1];

  const numericValue = Number(raw);
  if (!Number.isNaN(numericValue)) {
    const fromNumericString = new Date(numericValue);
    if (!Number.isNaN(fromNumericString.getTime())) {
      return fromNumericString.toISOString().split('T')[0];
    }
  }

  const parsed = new Date(raw);
  return Number.isNaN(parsed.getTime()) ? '' : parsed.toISOString().split('T')[0];
}

function getFixDate(vuln) {
  return normalizeDateToYmd(
    vuln.fixedDate
    || vuln.lastFixedDate
    || vuln.resolvedDate
    || vuln.lastFixed
    || vuln.lastTest
    || vuln.lastFound
    || vuln.detectionUpdated
    || null
  );
}

function normalizeFixDateRange(start, end) {
  return normalizeDateRange(start, end);
}

function filterByDate(vulnerabilities, start, end) {
  const { startDate, endDate } = normalizeDateRange(start, end);
  return vulnerabilities.filter((vuln) => {
    const detectedAt = getDetectedAt(vuln);
    return detectedAt && detectedAt >= startDate && detectedAt <= endDate;
  });
}

function filterByFixDate(vulnerabilities, start, end) {
  const { startDate, endDate } = normalizeFixDateRange(start, end);
  return vulnerabilities.filter((vuln) => {
    if (getStatusValue(vuln) !== 'FIXED') return false;
    const fixDate = getFixDate(vuln);
    return fixDate && fixDate >= startDate && fixDate <= endDate;
  });
}

function applyDateFilters(vulnerabilities, mode, detectionRange, fixRange) {
  if (mode === 'fix') {
    const fixedVulnerabilities = filterByFixDate(vulnerabilities, fixRange.startDate, fixRange.endDate);
    const openVulnerabilities = vulnerabilities.filter((vuln) => getStatusValue(vuln) !== 'FIXED');
    return [...openVulnerabilities, ...fixedVulnerabilities];
  }

  if (mode === 'combined') {
    const { startDate: detectionStart, endDate: detectionEnd } = normalizeDateRange(
      detectionRange.startDate,
      detectionRange.endDate
    );
    const { startDate: fixStart, endDate: fixEnd } = normalizeFixDateRange(
      fixRange.startDate,
      fixRange.endDate
    );

    const openVulnerabilities = vulnerabilities.filter((vuln) => {
      if (getStatusValue(vuln) === 'FIXED') return false;
      const detectedAt = getDetectedAt(vuln);
      return detectedAt && detectedAt >= detectionStart && detectedAt <= detectionEnd;
    });

    const fixedVulnerabilities = vulnerabilities.filter((vuln) => {
      if (getStatusValue(vuln) !== 'FIXED') return false;
      const fixDate = getFixDate(vuln);
      return fixDate && fixDate >= fixStart && fixDate <= fixEnd;
    });

    return [...openVulnerabilities, ...fixedVulnerabilities];
  }

  return filterByDate(vulnerabilities, detectionRange.startDate, detectionRange.endDate);
}

function severityKey(vuln) {
  const severity = String(vuln.severity || '').toUpperCase();
  if (severity === 'CRITICAL' || severity === '5') return 'critical';
  if (severity === 'HIGH' || severity === '4') return 'high';
  return 'medium';
}

function calcKpis(vulnerabilitiesFiltradas) {
  const hostIds = new Set();
  const severityDistribution = { critical: 0, high: 0, medium: 0 };

  vulnerabilitiesFiltradas.forEach((vuln) => {
    const sev = severityKey(vuln);
    severityDistribution[sev] += 1;
    hostIds.add(vuln.hostId || vuln.hostIp || vuln.hostDns || 'unknown');
  });

  return {
    totalHosts: hostIds.size,
    totalVulnerabilities: vulnerabilitiesFiltradas.length,
    severityDistribution
  };
}

function getStatusValue(vuln) {
  return String(
    vuln.status
    || vuln.detectionStatus
    || vuln.findingStatus
    || vuln.state
    || ''
  ).trim().toUpperCase();
}

function isFixedVuln(vuln) {
  if (typeof vuln.isFixed === 'boolean') return vuln.isFixed;
  const status = getStatusValue(vuln);
  return status === 'FIXED';
}

function calcChartSeries(vulnerabilitiesFiltradas, trendDateSelector = getDetectedAt) {
  const qidCount = {};
  const dateCount = {};
  const emptyBucket = () => ({ abertas: 0, corrigidas: 0 });
  const tagDistribution = {
    DEV_QA: { critical: emptyBucket(), high: emptyBucket(), medium: emptyBucket(), total: 0 },
    PRD_Baixa: { critical: emptyBucket(), high: emptyBucket(), medium: emptyBucket(), total: 0 },
    PRD_Alta: { critical: emptyBucket(), high: emptyBucket(), medium: emptyBucket(), total: 0 }
  };

  vulnerabilitiesFiltradas.forEach((vuln) => {
    const sev = severityKey(vuln);
    const qid = vuln.qid || 'Unknown';
    qidCount[qid] = (qidCount[qid] || 0) + 1;

    const trendDate = trendDateSelector(vuln);
    if (trendDate) dateCount[trendDate] = (dateCount[trendDate] || 0) + 1;

    const windowKey = findWindowByTags(vuln.hostTags || '');
    if (windowKey) {
      const statusBucket = isFixedVuln(vuln) ? 'corrigidas' : 'abertas';
      tagDistribution[windowKey][sev][statusBucket] += 1;
      tagDistribution[windowKey].total += 1;
    }
  });

  return {
    topVulnerabilities: Object.entries(qidCount)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([qid, count]) => ({ qid, count })),
    trends: Object.entries(dateCount)
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([date, count]) => ({ date, count })),
    tagDistribution
  };
}

function renderDashboardWithView() {
  const source = dashboardState.vulnerabilities;
  const isDetalhada = dashboardState.selectedView === 'detalhada';
  const filtered = isDetalhada
    ? applyDateFilters(
      source,
      dashboardState.dateFilterMode,
      { startDate: dashboardState.startDate, endDate: dashboardState.endDate },
      { startDate: dashboardState.fixStartDate, endDate: dashboardState.fixEndDate }
    )
    : source;

  const trendDateSelector = isDetalhada && dashboardState.dateFilterMode === 'fix'
    ? getFixDate
    : getDetectedAt;
  const kpis = calcKpis(filtered);
  const chartSeries = calcChartSeries(filtered, trendDateSelector);

  const hasData = filtered.length > 0;
  const emptyState = document.getElementById('dashboardEmptyState');
  const chartsContent = document.getElementById('dashboardChartsContent');

  if (emptyState && chartsContent) {
    if (hasData) {
      emptyState.style.display = 'none';
      chartsContent.style.display = 'block';
    } else {
      emptyState.style.display = 'block';
      chartsContent.style.display = 'none';
    }
  }

  document.getElementById('totalHosts').textContent = kpis.totalHosts;
  document.getElementById('totalVulns').textContent = kpis.totalVulnerabilities;
  document.getElementById('criticalVulns').textContent = kpis.severityDistribution.critical;
  document.getElementById('highVulns').textContent = kpis.severityDistribution.high;
  document.getElementById('mediumVulns').textContent = kpis.severityDistribution.medium;

  if (hasData) {
    updateCharts({ ...kpis, ...chartSeries }, { trends: chartSeries.trends });
  }
}

function syncDashboardViewControls() {
  const isDetalhada = dashboardState.selectedView === 'detalhada';
  const selector = document.getElementById('dashboardViewSelector');
  const dateFilter = document.getElementById('dashboardDateFilter');
  const geralBtn = document.getElementById('viewGeralBtn');
  const detalhadaBtn = document.getElementById('viewDetalhadaBtn');
  const modeSelector = document.getElementById('dateFilterModeSelector');
  const detectionRangeGroup = document.getElementById('detectionDateRangeGroup');
  const fixRangeGroup = document.getElementById('fixDateRangeGroup');
  const detectionInputs = [document.getElementById('dashboardStartDate'), document.getElementById('dashboardEndDate')];
  const fixInputs = [document.getElementById('dashboardFixStartDate'), document.getElementById('dashboardFixEndDate')];
  const isDetectionMode = dashboardState.dateFilterMode === 'detection';
  const isFixMode = dashboardState.dateFilterMode === 'fix';
  const isCombinedMode = dashboardState.dateFilterMode === 'combined';

  if (selector) selector.style.display = document.getElementById('dashboard').classList.contains('active') ? 'inline-flex' : 'none';
  if (dateFilter) dateFilter.style.display = isDetalhada ? 'block' : 'none';
  if (modeSelector) modeSelector.style.display = isDetalhada ? 'inline-flex' : 'none';
  if (geralBtn) {
    geralBtn.classList.toggle('active', !isDetalhada);
    geralBtn.setAttribute('aria-selected', String(!isDetalhada));
  }
  if (detalhadaBtn) {
    detalhadaBtn.classList.toggle('active', isDetalhada);
    detalhadaBtn.setAttribute('aria-selected', String(isDetalhada));
  }

  document.querySelectorAll('.date-mode-option').forEach((button) => {
    const isActive = button.dataset.mode === dashboardState.dateFilterMode;
    button.classList.toggle('active', isActive);
    button.setAttribute('aria-selected', String(isActive));
  });

  if (detectionRangeGroup) {
    detectionRangeGroup.classList.toggle('range-disabled', isFixMode);
  }

  if (fixRangeGroup) {
    fixRangeGroup.classList.toggle('range-disabled', isDetectionMode);
  }

  detectionInputs.forEach((input) => {
    if (!input) return;
    input.disabled = isFixMode;
  });

  fixInputs.forEach((input) => {
    if (!input) return;
    input.disabled = isDetectionMode;
  });

  if (!isDetalhada || isCombinedMode) {
    detectionInputs.forEach((input) => {
      if (input) input.disabled = false;
    });
    fixInputs.forEach((input) => {
      if (input) input.disabled = false;
    });
  }
}

function setDashboardView(view) {
  dashboardState.selectedView = view === 'detalhada' ? 'detalhada' : 'geral';
  syncDashboardViewControls();
  renderDashboardWithView();
}

function handleDashboardDateChange() {
  const startInput = document.getElementById('dashboardStartDate');
  const endInput = document.getElementById('dashboardEndDate');
  const fixStartInput = document.getElementById('dashboardFixStartDate');
  const fixEndInput = document.getElementById('dashboardFixEndDate');

  try {
    const normalized = normalizeDateRange(startInput.value, endInput.value);
    const normalizedFix = normalizeFixDateRange(fixStartInput.value, fixEndInput.value);

    dashboardState.startDate = normalized.startDate;
    dashboardState.endDate = normalized.endDate;
    dashboardState.fixStartDate = normalizedFix.startDate;
    dashboardState.fixEndDate = normalizedFix.endDate;

    startInput.value = normalized.startDate;
    endInput.value = normalized.endDate;
    fixStartInput.value = normalizedFix.startDate;
    fixEndInput.value = normalizedFix.endDate;

    renderDashboardWithView();
  } catch (error) {
    showMessage(error.message, 'error');
  }
}

function setDashboardDateFilterMode(mode) {
  const allowedModes = new Set(['detection', 'fix', 'combined']);
  dashboardState.dateFilterMode = allowedModes.has(mode) ? mode : 'detection';
  syncDashboardViewControls();
  renderDashboardWithView();
}

async function loadDashboard() {
  try {
    showLoading(true);

    const vulnerabilitiesResponse = await apiCall('/api/vulnerabilities');
    const queued = handleQueueResponse(vulnerabilitiesResponse);

    if (!Array.isArray(vulnerabilitiesResponse?.data)) {
      throw new Error(vulnerabilitiesResponse?.message || 'Dados do dashboard indisponíveis no momento.');
    }

    dashboardState.vulnerabilities = vulnerabilitiesResponse.data.filter((v) => ['3', '4', '5', 'CRITICAL', 'HIGH', 'MEDIUM'].includes(String(v.severity).toUpperCase()));
    console.log('FIXED sample:', dashboardState.vulnerabilities.filter((v) => getStatusValue(v) === 'FIXED').slice(0, 5));

    const startInput = document.getElementById('dashboardStartDate');
    const endInput = document.getElementById('dashboardEndDate');
    const fixStartInput = document.getElementById('dashboardFixStartDate');
    const fixEndInput = document.getElementById('dashboardFixEndDate');

    const normalized = normalizeDateRange(startInput.value, endInput.value);
    const normalizedFix = normalizeFixDateRange(fixStartInput.value, fixEndInput.value);

    dashboardState.startDate = normalized.startDate;
    dashboardState.endDate = normalized.endDate;
    dashboardState.fixStartDate = normalizedFix.startDate;
    dashboardState.fixEndDate = normalizedFix.endDate;

    startInput.value = normalized.startDate;
    endInput.value = normalized.endDate;
    fixStartInput.value = normalizedFix.startDate;
    fixEndInput.value = normalizedFix.endDate;

    syncDashboardViewControls();
    renderDashboardWithView();

    showLoading(false);
    if (!queued) showMessage('Dashboard atualizado com sucesso!', 'success');
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
      legend: { display: true, labels: { color: '#f0f4f8' } },
      title: {
        display: true,
        text: title,
        color: '#f0f4f8'
      }
    },
    scales: {
      x: { stacked: true, grid: { display: false } },
      y: { stacked: true, beginAtZero: true, grid: { color: '#1a223a' } }
    }
  });

  // --- Gráfico Desenvolvimento e Qualidade (DEV_QA) ---
  if (charts.devQA) charts.devQA.destroy();
  const devQACtx = document.getElementById('devQAChart').getContext('2d');
  charts.devQA = new Chart(devQACtx, {
    type: 'bar',
    data: {
      labels: ['Crítica', 'Alta', 'Média'],
      datasets: [
        {
          label: 'Abertas',
          data: [
            summary.tagDistribution?.DEV_QA?.critical?.abertas || 0,
            summary.tagDistribution?.DEV_QA?.high?.abertas || 0,
            summary.tagDistribution?.DEV_QA?.medium?.abertas || 0
          ],
          backgroundColor: [sevColors[0], sevColors[1], sevColors[2]],
          stack: 'vulnerabilidades'
        },
        {
          label: 'Corrigidas',
          data: [
            summary.tagDistribution?.DEV_QA?.critical?.corrigidas || 0,
            summary.tagDistribution?.DEV_QA?.high?.corrigidas || 0,
            summary.tagDistribution?.DEV_QA?.medium?.corrigidas || 0
          ],
          backgroundColor: '#22c55e',
          stack: 'vulnerabilidades'
        }
      ]
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
      datasets: [
        {
          label: 'Abertas',
          data: [
            summary.tagDistribution?.PRD_Baixa?.critical?.abertas || 0,
            summary.tagDistribution?.PRD_Baixa?.high?.abertas || 0,
            summary.tagDistribution?.PRD_Baixa?.medium?.abertas || 0
          ],
          backgroundColor: [sevColors[0], sevColors[1], sevColors[2]],
          stack: 'vulnerabilidades'
        },
        {
          label: 'Corrigidas',
          data: [
            summary.tagDistribution?.PRD_Baixa?.critical?.corrigidas || 0,
            summary.tagDistribution?.PRD_Baixa?.high?.corrigidas || 0,
            summary.tagDistribution?.PRD_Baixa?.medium?.corrigidas || 0
          ],
          backgroundColor: '#22c55e',
          stack: 'vulnerabilidades'
        }
      ]
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
      datasets: [
        {
          label: 'Abertas',
          data: [
            summary.tagDistribution?.PRD_Alta?.critical?.abertas || 0,
            summary.tagDistribution?.PRD_Alta?.high?.abertas || 0,
            summary.tagDistribution?.PRD_Alta?.medium?.abertas || 0
          ],
          backgroundColor: [sevColors[0], sevColors[1], sevColors[2]],
          stack: 'vulnerabilidades'
        },
        {
          label: 'Corrigidas',
          data: [
            summary.tagDistribution?.PRD_Alta?.critical?.corrigidas || 0,
            summary.tagDistribution?.PRD_Alta?.high?.corrigidas || 0,
            summary.tagDistribution?.PRD_Alta?.medium?.corrigidas || 0
          ],
          backgroundColor: '#22c55e',
          stack: 'vulnerabilidades'
        }
      ]
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

function parseDetectionIds(input = '') {
  if (typeof input !== 'string') return [];
  const tokens = input
    .split(/[\n,;\s]+/)
    .map((token) => token.trim())
    .filter(Boolean);

  return Array.from(new Set(tokens));
}

function classifyDetectionIds(ids = [], activeSet = new Set()) {
  const uniqueIds = Array.from(new Set(ids.map((id) => String(id).trim()).filter(Boolean)));
  const items = uniqueIds.map((detectionId) => {
    if (!/^\d+$/.test(detectionId)) {
      return { detectionId, status: 'invalid' };
    }

    return {
      detectionId,
      status: activeSet.has(detectionId) ? 'open' : 'fixed'
    };
  });

  return items.reduce((acc, item) => {
    acc.total += 1;
    if (item.status === 'open') acc.open += 1;
    if (item.status === 'fixed') acc.fixed += 1;
    if (item.status === 'invalid') acc.invalid += 1;
    acc.items.push(item);
    return acc;
  }, { total: 0, fixed: 0, open: 0, invalid: 0, items: [] });
}

function clearEffectivenessView() {
  document.getElementById('efetividadeKpis').style.display = 'none';
  document.getElementById('efetividadeCharts').style.display = 'none';
  document.getElementById('efetividadeFilterSection').style.display = 'none';
  document.getElementById('efetividadeTableWrapper').style.display = 'none';
  document.getElementById('efetividadeTableBody').innerHTML = '';
}

function statusLabel(status) {
  if (status === 'open') return 'Pendente';
  if (status === 'fixed') return 'Corrigida';
  return 'Inválida';
}

function statusClass(status) {
  if (status === 'open') return 'severity-high';
  if (status === 'fixed') return 'severity-low';
  return 'severity-critical';
}

function formatLastSeen(value) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  return new Intl.DateTimeFormat('pt-BR', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  }).format(date);
}

function getEffectivenessFilteredItems(data) {
  const selectedTag = document.getElementById('effectivenessTagFilter').value;
  const dnsFilter = document.getElementById('effectivenessDnsFilter').value.toLowerCase().trim();
  const severities = Array.from(document.querySelectorAll('.effectiveness-severity-filter:checked')).map((cb) => cb.value);

  return (data.items || []).filter((item) => {
    const byTag = !selectedTag || (item.hostTags || []).includes(selectedTag);
    const byDns = !dnsFilter || String(item.dns || '').toLowerCase().includes(dnsFilter);
    const bySeverity = severities.length === 0 || severities.includes(item.severity || 'Info');
    return byTag && byDns && bySeverity;
  });
}

function effectivenessSummary(items = []) {
  return items.reduce((acc, item) => {
    acc.total += 1;
    if (item.status === 'open') acc.open += 1;
    if (item.status === 'fixed') acc.fixed += 1;
    if (item.status === 'invalid') acc.invalid += 1;
    return acc;
  }, { total: 0, open: 0, fixed: 0, invalid: 0 });
}

function buildEffectivenessCharts(data, items) {
  const summary = effectivenessSummary(items);

  if (charts.effectivenessDonut) charts.effectivenessDonut.destroy();
  const donutCtx = document.getElementById('effectivenessDonutChart').getContext('2d');
  charts.effectivenessDonut = new Chart(donutCtx, {
    type: 'doughnut',
    data: {
      labels: ['Corrigidas', 'Pendentes', 'Inválidas'],
      datasets: [{
        data: [summary.fixed, summary.open, summary.invalid],
        backgroundColor: ['#2ecc71', '#f1c40f', '#e63946'],
        borderWidth: 0
      }]
    },
    options: { responsive: true, maintainAspectRatio: false }
  });

  if (charts.effectivenessBar) charts.effectivenessBar.destroy();
  const barCtx = document.getElementById('effectivenessBarChart').getContext('2d');
  charts.effectivenessBar = new Chart(barCtx, {
    type: 'bar',
    data: {
      labels: ['Corrigidas', 'Pendentes', 'Inválidas'],
      datasets: [{
        data: [summary.fixed, summary.open, summary.invalid],
        backgroundColor: ['#2ecc71', '#f1c40f', '#e63946'],
        borderRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: { y: { beginAtZero: true, grid: { color: '#1a223a' } }, x: { grid: { display: false } } }
    }
  });

  const severities = ['Crítica', 'Alta', 'Média'];
  const sevStatus = severities.map((severity) => {
    const subset = items.filter((item) => item.severity === severity);
    return {
      open: subset.filter((item) => item.status === 'open').length,
      fixed: subset.filter((item) => item.status === 'fixed').length
    };
  });

  if (charts.effectivenessSeverityStatus) charts.effectivenessSeverityStatus.destroy();
  const sevStatusCtx = document.getElementById('effectivenessSeverityStatusChart').getContext('2d');
  charts.effectivenessSeverityStatus = new Chart(sevStatusCtx, {
    type: 'bar',
    data: {
      labels: severities,
      datasets: [
        { label: 'Pendentes', data: sevStatus.map((v) => v.open), backgroundColor: '#f1c40f' },
        { label: 'Corrigidas', data: sevStatus.map((v) => v.fixed), backgroundColor: '#2ecc71' }
      ]
    },
    options: { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true } } }
  });

  const severityDistribution = severities.map((severity) => items.filter((item) => item.severity === severity).length);
  const others = items.filter((item) => !severities.includes(item.severity)).length;

  if (charts.effectivenessSeverityDistribution) charts.effectivenessSeverityDistribution.destroy();
  const sevDistCtx = document.getElementById('effectivenessSeverityDistributionChart').getContext('2d');
  charts.effectivenessSeverityDistribution = new Chart(sevDistCtx, {
    type: 'doughnut',
    data: {
      labels: others > 0 ? [...severities, 'Outros'] : severities,
      datasets: [{
        data: others > 0 ? [...severityDistribution, others] : severityDistribution,
        backgroundColor: ['#e63946', '#ff8c42', '#f1c40f', '#6b7280']
      }]
    },
    options: { responsive: true, maintainAspectRatio: false }
  });
}

function populateEffectivenessFilters(data) {
  const allTags = Array.from(new Set((data.items || []).flatMap((item) => item.hostTags || []))).sort();
  const tagSelect = document.getElementById('effectivenessTagFilter');
  tagSelect.innerHTML = '<option value="">Todas as Tags</option>' + allTags.map((tag) => `<option value="${tag}">${tag}</option>`).join('');
}

function renderEffectivenessTable(items) {
  document.getElementById('efetividadeTableBody').innerHTML = items.map((item) => `
    <tr>
      <td>${item.detectionId}</td>
      <td class="${statusClass(item.status)}">${statusLabel(item.status)}</td>
      <td>${item.dns || '-'}</td>
      <td>${item.ip || '-'}</td>
      <td>${item.title || '-'}</td>
      <td>${item.severity || '-'}</td>
      <td>${formatLastSeen(item.lastSeen)}</td>
      <td>${item.solution || '-'}</td>
    </tr>
  `).join('');
}

function applyEffectivenessFilters() {
  const data = currentData.effectiveness;
  if (!data) return;

  const filteredItems = getEffectivenessFilteredItems(data);
  const summary = effectivenessSummary(filteredItems);

  document.getElementById('efetividadeTotal').textContent = summary.total;
  document.getElementById('efetividadeFixed').textContent = summary.fixed;
  document.getElementById('efetividadeOpen').textContent = summary.open;
  document.getElementById('efetividadeInvalid').textContent = summary.invalid;

  buildEffectivenessCharts(data, filteredItems);
  renderEffectivenessTable(filteredItems);
}

function clearEffectivenessFilters() {
  document.getElementById('effectivenessTagFilter').value = '';
  document.getElementById('effectivenessDnsFilter').value = '';
  document.querySelectorAll('.effectiveness-severity-filter').forEach((checkbox) => {
    checkbox.checked = true;
  });
  applyEffectivenessFilters();
}

function renderEffectiveness(data) {
  currentData.effectiveness = data;

  document.getElementById('efetividadeKpis').style.display = 'grid';
  document.getElementById('efetividadeCharts').style.display = 'grid';
  document.getElementById('efetividadeFilterSection').style.display = 'block';
  document.getElementById('efetividadeTableWrapper').style.display = 'block';

  populateEffectivenessFilters(data);
  applyEffectivenessFilters();
}

async function analyzeEffectiveness() {
  const input = document.getElementById('effectivenessInput').value;
  const detectionIds = parseDetectionIds(input);

  if (!detectionIds.length) {
    showMessage('Informe ao menos um Detection ID para analisar.', 'warning');
    return;
  }

  try {
    showLoading(true);
    const response = await fetch('/api/effectiveness', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Basic ' + btoa('admin:admin123')
      },
      body: JSON.stringify({ detectionIds })
    });

    const data = await response.json();

    if (isQueuedResponse(data)) {
      showMessage(buildQueueMessage(data), 'warning');
      if (data.items) {
        renderEffectiveness(data);
      }
      return;
    }

    if (!response.ok || !data.success) {
      throw new Error(data.message || data.error || 'Erro ao analisar efetividade.');
    }

    renderEffectiveness(data);
    showMessage('Análise de efetividade concluída com sucesso!', 'success');
  } catch (error) {
    showMessage(error.message || 'Erro ao analisar efetividade.', 'error');
  } finally {
    showLoading(false);
  }
}

function clearEffectiveness() {
  document.getElementById('effectivenessInput').value = '';
  currentData.effectiveness = null;
  clearEffectivenessView();
}

async function loadVulnerabilities() {
  try {
    showLoading(true);
    const data = await apiCall('/api/vulnerabilities');
    const queued = handleQueueResponse(data);

    if (!Array.isArray(data?.data)) {
      throw new Error(data?.message || data?.error || 'Não foi possível carregar vulnerabilidades no momento.');
    }

    currentData.vulnerabilities = data.data || [];
    currentData.filteredVulnerabilities = data.data || [];
    currentData.availableTags = extractTagsFromVulns(currentData.vulnerabilities);
    populateTagFilter(currentData.availableTags);
    selectedStatuses = selectedStatuses.filter((status) => getAvailableStatuses(currentData.vulnerabilities).includes(status));
    renderStatusFilterOptions();
    displayVulnerabilities(currentData.vulnerabilities);
    document.getElementById('vulnTotal').textContent = currentData.vulnerabilities.length;
    showLoading(false);
    if (!queued) {
      showMessage('Vulnerabilidades carregadas!', 'success');
    }
  } catch (error) {
    showLoading(false);
    showMessage('Erro ao carregar vulnerabilidades: ' + error.message, 'error');
  }
}

function displayVulnerabilities(vulns) {
  const severityLabel = { '5': 'Crítica', '4': 'Alta', '3': 'Média', '2': 'Baixa', '1': 'Info' };
  const severityClass = { '5': 'critical', '4': 'high', '3': 'medium', '2': 'low', '1': 'low' };

  document.getElementById('vulnCount').textContent = vulns.length;
  document.getElementById('vulnTableBody').innerHTML = vulns.map(v => `
    <tr>
      <td>${getOfficialDetectionId(v)}</td>
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
  `).join('');
}

document.addEventListener('click', (event) => {
  const dropdown = document.getElementById('statusFilterDropdown');
  if (!dropdown || dropdown.contains(event.target)) return;
  toggleStatusDropdown(false);
});

function applyFilters() {
  const selectedSeverities = Array.from(document.querySelectorAll('.severity-filter:checked'))
    .map(cb => cb.value);

  const quickSearch = document.getElementById('quickSearch').value.toLowerCase().trim();
  const quickSearchUpper = quickSearch.toUpperCase();
  const qid = document.getElementById('filterQid').value.trim();
  const selectedTag = document.getElementById('tagFilter').value;

  let filtered = currentData.vulnerabilities;
  const hasStatusFilter = selectedStatuses.length > 0;

  const hasActiveFilters = selectedSeverities.length < 5 || quickSearch || qid || selectedTag || hasStatusFilter;

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
      const officialDetectionId = getOfficialDetectionId(v);
      const targets = [officialDetectionId, v.hostIp, v.hostDns, v.title, v.os, v.solution, v.status, v.port, v.qid];
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
  if (hasStatusFilter) {
    filtered = filtered.filter(v => selectedStatuses.includes(v.status));
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
  selectedStatuses = [];
  renderStatusFilterOptions();
  toggleStatusDropdown(false);

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
      const detectionId = getOfficialDetectionId(vuln);
      const row = [
        detectionId,
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
    handleQueueResponse(data);

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
  syncDashboardViewControls();
  loadDashboard();
  clearEffectivenessView();
};
