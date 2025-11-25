const express = require('express');
const axios = require('axios');
const https = require('https');
const xml2js = require('xml2js');
const ExcelJS = require('exceljs');
const cors = require('cors');
const basicAuth = require('express-basic-auth');
const path = require('path');
const fs = require('fs');
require('dotenv').config(); // Carrega variáveis de ambiente

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Configuração do Qualys usando variáveis de ambiente
const QUALYS_CONFIG = {
  username: process.env.QUALYS_USERNAME,
  password: process.env.QUALYS_PASSWORD,
  baseURL: process.env.QUALYS_BASE_URL || 'https://qualysguard.qg3.apps.qualys.com'
};

// Valida se as credenciais foram fornecidas
if (!QUALYS_CONFIG.username || !QUALYS_CONFIG.password) {
  console.error('ERRO: Credenciais do Qualys não configuradas!');
  console.error('Crie um arquivo .env com QUALYS_USERNAME e QUALYS_PASSWORD');
  process.exit(1);
}

const auth = basicAuth({
  users: { 
    [process.env.API_USERNAME || 'admin']: process.env.API_PASSWORD || 'admin123' 
  },
  challenge: true,
  realm: 'Qualys API'
});

const cache = {
  vulnerabilities: {
    data: null,
    lastUpdate: null
  },
  hosts: {
    data: null,
    lastUpdate: null
  },
  ttl: 300000
};

const MAX_KB_CONCURRENCY = 5;

const formatErrorMessage = (error) => {
  if (error.response) {
    const { status, statusText, data } = error.response;
    const responseBody = typeof data === 'string' ? data.slice(0, 500) : JSON.stringify(data);
    return `HTTP ${status} ${statusText || ''} - ${responseBody}`.trim();
  }

  if (error.request) {
    return 'No response received from Qualys API';
  }

  return error.message || 'Unknown error';
};

const getCachedData = async (cacheEntry, fetchFunction) => {
  const now = Date.now();
  if (cacheEntry.data && cacheEntry.lastUpdate && now - cacheEntry.lastUpdate < cache.ttl) {
    return { data: cacheEntry.data, cached: true, stale: false };
  }

  try {
    const data = await fetchFunction();
    cacheEntry.data = data;
    cacheEntry.lastUpdate = now;
    return { data, cached: false, stale: false };
  } catch (error) {
    if (cacheEntry.data) {
      console.warn('Falha ao atualizar, retornando dados em cache:', error.message);
      return { data: cacheEntry.data, cached: true, stale: true };
    }
    throw error;
  }
};

const qualysClient = axios.create({
  baseURL: QUALYS_CONFIG.baseURL,
  auth: {
    username: QUALYS_CONFIG.username,
    password: QUALYS_CONFIG.password
  },
  headers: {
    'X-Requested-With': 'API'
  },
  httpsAgent: new https.Agent({  
    rejectUnauthorized: false
  })
});

class QualysAPI {
  async getHostList() {
    try {
      const response = await qualysClient.get('/api/2.0/fo/asset/host/', {
        params: {
          action: 'list',
          truncation_limit: '0',
          show_tags: '1'
        }
      });
      return await this.parseHostXML(response.data);
    } catch (error) {
      console.error('Erro ao obter hosts:', error.message);
      throw error;
    }
  }

  async getVulnerabilities() {
    try {
      const response = await qualysClient.get('/api/2.0/fo/asset/host/vm/detection/', {
        params: {
          action: 'list',
          truncation_limit: '1000',
          status: 'New,Active,Re-Opened',
          output_format: 'XML',
          show_tags: '1'
        },
        timeout: 120000
      });
      return await this.buildVulnerabilitiesFromXml(response.data);
    } catch (error) {
      console.error('Erro ao obter vulnerabilidades (Tentativa 1):', error.message);
      
      if (error.response?.status === 409) {
        console.log('Tentando com limite menor...');
        try {
          const response = await qualysClient.get('/api/2.0/fo/asset/host/vm/detection/', {
            params: {
              action: 'list',
              truncation_limit: '500',
              status: 'New,Active,Re-Opened',
              output_format: 'XML',
              show_tags: '1'
          },
          timeout: 120000
        });
          return await this.buildVulnerabilitiesFromXml(response.data);
        } catch (retryError) {
          console.error('Erro na segunda tentativa:', retryError.message);
          throw retryError;
        }
      }
      throw error;
    }
  }

  async buildVulnerabilitiesFromXml(xmlData) {
    const parsedVulnerabilities = await this.parseVulnerabilityXML(xmlData);
    const uniqueQids = new Set(parsedVulnerabilities.map(vuln => vuln.qid).filter(Boolean));
    const kbDetails = await this.fetchKnowledgeBaseDetails(uniqueQids);

    return parsedVulnerabilities.map(vuln => {
      const kb = kbDetails[vuln.qid] || {};
      const normalizedDetectionId = vuln.uniqueVulnId || vuln.detectionId || '';

      return {
        ...vuln,
        detectionId: normalizedDetectionId,
        uniqueVulnId: normalizedDetectionId,
        title: vuln.title || kb.title || '',
        solution: vuln.solution || kb.solution || ''
      };
    });
  }

  async getScanList() {
    try {
      const response = await qualysClient.get('/api/2.0/fo/scan/', {
        params: {
          action: 'list'
        }
      });
      return await this.parseScanXML(response.data);
    } catch (error) {
      console.error('Erro ao obter scans:', error.message);
      throw error;
    }
  }

  async parseHostXML(xmlData) {
    const parser = new xml2js.Parser({ explicitArray: false });
    const result = await parser.parseStringPromise(xmlData);
    
    const hosts = [];
    const hostList = result?.HOST_LIST_OUTPUT?.RESPONSE?.HOST_LIST?.HOST;
    
    if (!hostList) return hosts;
    
    const hostArray = Array.isArray(hostList) ? hostList : [hostList];
    
    hostArray.forEach(host => {
      let tags = '';
      if (host.TAGS) {
        const tagList = host.TAGS.TAG;
        if (tagList) {
          const tagArray = Array.isArray(tagList) ? tagList : [tagList];
          tags = tagArray.map(tag => {
            const tagName = tag.NAME || tag;
            return String(tagName).replace(/\s+/g, '_').replace(/\//g, '_');
          }).join(', ');
        }
      }
      
      hosts.push({
        id: host.ID || '',
        ip: host.IP || '',
        trackingMethod: host.TRACKING_METHOD || '',
        dns: host.DNS || '',
        netbios: host.NETBIOS || '',
        os: host.OS || '',
        lastVulnScan: host.LAST_VULN_SCAN_DATETIME || '',
        tags: tags
      });
    });
    
    return hosts;
  }

  async parseHostDetectionXML(xmlData) {
    const parser = new xml2js.Parser({ explicitArray: false });
    const result = await parser.parseStringPromise(xmlData);

    const detections = [];
    const hostList = result?.HOST_LIST_VM_DETECTION_OUTPUT?.RESPONSE?.HOST_LIST?.HOST;
    if (!hostList) return detections;

    const hostArray = Array.isArray(hostList) ? hostList : [hostList];

    hostArray.forEach(host => {
      const ip = host.IP || '';
      const dns = host.DNS || '';
      const os = host.OS || '';

      let hostTags = '';
      if (host.TAGS) {
        const tagList = host.TAGS.TAG;
        if (tagList) {
          const tagArray = Array.isArray(tagList) ? tagList : [tagList];
          hostTags = tagArray.map(tag => {
            const tagName = tag.NAME || tag;
            return String(tagName).replace(/\s+/g, '_').replace(/\//g, '_');
          }).join(', ');
        }
      }

      const detectionList = host.DETECTION_LIST?.DETECTION;
      if (!detectionList) return;

      const detectionArray = Array.isArray(detectionList) ? detectionList : [detectionList];

      detectionArray.forEach(detection => {
        detections.push({
          hostIp: ip,
          hostDns: dns,
          hostTags,
          os,
          qid: detection.QID || '',
          severity: detection.SEVERITY || '',
          status: detection.STATUS || '',
          firstFound: detection.FIRST_FOUND_DATETIME || '',
          lastFound: detection.LAST_FOUND_DATETIME || ''
        });
      });
    });

    return detections;
  }

  async parseVulnerabilityXML(xmlData) {
    const parser = new xml2js.Parser({ explicitArray: false });
    const result = await parser.parseStringPromise(xmlData);

    const vulnerabilities = [];
    const hostList = result?.HOST_LIST_VM_DETECTION_OUTPUT?.RESPONSE?.HOST_LIST?.HOST;

    if (!hostList) return vulnerabilities;

    const hostArray = Array.isArray(hostList) ? hostList : [hostList];

    hostArray.forEach(host => {
      const hostId = host.ID || host.IP || '';
      const ip = host.IP || '';
      const dns = host.DNS || '';
      const os = host.OS || '';

      let hostTags = '';
      if (host.TAGS) {
        const tagList = host.TAGS.TAG;
        if (tagList) {
          const tagArray = Array.isArray(tagList) ? tagList : [tagList];
          hostTags = tagArray.map(tag => {
            const tagName = tag.NAME || tag;
            return String(tagName).replace(/\s+/g, '_').replace(/\//g, '_');
          }).join(', ');
        }
      }
      
      const detections = host.DETECTION_LIST?.DETECTION;
      if (!detections) return;

      const detectionArray = Array.isArray(detections) ? detections : [detections];

      detectionArray.forEach(detection => {
        const qid = detection.QID || '';
        const composedId = `${hostId}-${qid}`;
        const uniqueVulnId = detection.UNIQUE_VULN_ID || detection.VULN_INFO?.UNIQUE_VULN_ID || composedId;

        vulnerabilities.push({
          detectionId: composedId,
          uniqueVulnId,
          hostId,
          hostIp: ip,
          hostDns: dns,
          hostTags: hostTags,
          os,
          qid,
          type: detection.TYPE || '',
          severity: detection.SEVERITY || '',
          status: detection.STATUS || '',
          firstFound: detection.FIRST_FOUND_DATETIME || '',
          lastFound: detection.LAST_FOUND_DATETIME || '',
          port: detection.PORT || '',
          protocol: detection.PROTOCOL || '',
          ssl: detection.SSL || '',
          title: detection.VULN_INFO?.TITLE || '',
          solution: detection.VULN_INFO?.SOLUTION?.SOLUTION || detection.VULN_INFO?.SOLUTION || '',
          results: detection.RESULTS || ''
        });
      });
    });

    return vulnerabilities;
  }

  async parseKnowledgeBaseXML(xmlData) {
    const parser = new xml2js.Parser({ explicitArray: false });
    const result = await parser.parseStringPromise(xmlData);

    const details = {};
    const vulnList = result?.KNOWLEDGE_BASE_VULN_LIST_OUTPUT?.RESPONSE?.VULN_LIST?.VULN;
    if (!vulnList) return details;

    const vulnArray = Array.isArray(vulnList) ? vulnList : [vulnList];

    vulnArray.forEach(vuln => {
      const qid = vuln.QID || vuln.ID;
      if (!qid) return;

      const solutionValue = typeof vuln.SOLUTION === 'object' ? (vuln.SOLUTION.SOLUTION || vuln.SOLUTION) : vuln.SOLUTION;

      details[qid] = {
        title: vuln.TITLE || '',
        solution: solutionValue || ''
      };
    });

    return details;
  }

  async fetchKnowledgeBaseDetails(qids, concurrency = MAX_KB_CONCURRENCY) {
    const qidArray = Array.from(qids);
    const results = {};

    for (let i = 0; i < qidArray.length; i += concurrency) {
      const batch = qidArray.slice(i, i + concurrency);

      const responses = await Promise.all(batch.map(async qid => {
        try {
          const response = await qualysClient.get('/api/2.0/fo/knowledge_base/vuln/', {
            params: {
              action: 'list',
              ids: qid
            },
            timeout: 120000
          });

          const parsed = await this.parseKnowledgeBaseXML(response.data);
          return { qid, details: parsed[qid] };
        } catch (error) {
          console.warn(`Falha ao consultar QID ${qid}:`, formatErrorMessage(error));
          return { qid, details: null };
        }
      }));

      responses.forEach(({ qid, details }) => {
        if (details) {
          results[qid] = details;
        }
      });
    }

    return results;
  }

  async parseScanXML(xmlData) {
    const parser = new xml2js.Parser({ explicitArray: false });
    const result = await parser.parseStringPromise(xmlData);
    
    const scans = [];
    const scanList = result?.SCAN_LIST_OUTPUT?.RESPONSE?.SCAN_LIST?.SCAN;
    
    if (!scanList) return scans;
    
    const scanArray = Array.isArray(scanList) ? scanList : [scanList];
    
    scanArray.forEach(scan => {
      scans.push({
        ref: scan.REF || '',
        title: scan.TITLE || '',
        type: scan.TYPE || '',
        launchDate: scan.LAUNCH_DATETIME || '',
        state: scan.STATE?.STATE_NAME || '',
        target: scan.TARGET || ''
      });
    });

    return scans;
  }

  async getDetectionById(detectionId) {
    try {
      const response = await qualysClient.get('/api/2.0/fo/asset/host/vm/detection/', {
        params: {
          action: 'list',
          detection_ids: detectionId,
          output_format: 'XML',
          show_tags: '1'
        },
        timeout: 120000
      });

      const detections = await this.parseDetectionXML(response.data, detectionId);
      return detections[0] || null;
    } catch (error) {
      console.error(`Erro ao obter detection ${detectionId}:`, error.message);
      throw error;
    }
  }

  async getHostDetectionsWithDetails(concurrency = MAX_KB_CONCURRENCY) {
    try {
      const response = await qualysClient.get('/api/2.0/fo/asset/host/vm/detection/', {
        params: {
          action: 'list',
          truncation_limit: '0',
          output_format: 'XML',
          show_tags: '1'
        },
        timeout: 120000
      });

      const detections = await this.parseHostDetectionXML(response.data);
      const uniqueQids = new Set(detections.map(detection => detection.qid).filter(Boolean));
      const kbDetails = await this.fetchKnowledgeBaseDetails(uniqueQids, concurrency);

      return detections.map(detection => ({
        ...detection,
        ...(kbDetails[detection.qid] || {})
      }));
    } catch (error) {
      console.error('Erro ao obter detecções enriquecidas:', error.message);
      throw error;
    }
  }

  async parseDetectionXML(xmlData, fallbackId) {
    const parser = new xml2js.Parser({ explicitArray: false });
    const result = await parser.parseStringPromise(xmlData);

    const parsed = [];
    const hostList = result?.HOST_LIST_VM_DETECTION_OUTPUT?.RESPONSE?.HOST_LIST?.HOST;
    if (!hostList) return parsed;

    const hostArray = Array.isArray(hostList) ? hostList : [hostList];

    hostArray.forEach(host => {
      const hostName = host.DNS || host.IP || '';
      const hostTags = host.TAGS?.TAG;
      const normalizedTags = hostTags
        ? (Array.isArray(hostTags) ? hostTags : [hostTags])
          .map(tag => String(tag.NAME || tag).replace(/\s+/g, '_').replace(/\//g, '_'))
          .join(', ')
        : '';

      const detections = host.DETECTION_LIST?.DETECTION;
      if (!detections) return;

      const detectionArray = Array.isArray(detections) ? detections : [detections];
      detectionArray.forEach(detection => {
        parsed.push({
          detectionId: detection.DETECTION_ID || fallbackId,
          status: detection.STATUS || '',
          severity: detection.SEVERITY || '',
          qid: detection.QID || '',
          host: hostName,
          hostTags: normalizedTags,
          lastFound: detection.LAST_FOUND_DATETIME || detection.LAST_FOUND || ''
        });
      });
    });

    return parsed;
  }
}

const qualysAPI = new QualysAPI();

const detectionWindows = ['DEV_QA', 'PRD_Baixa', 'PRD_Alta'];

const readDetectionIdsFromCSV = async () => {
  const filePath = path.join(__dirname, 'detection_ids.csv');

  if (!fs.existsSync(filePath)) {
    throw new Error('Arquivo detection_ids.csv não encontrado na raiz da aplicação.');
  }

  const content = await fs.promises.readFile(filePath, 'utf-8');
  const lines = content.split(/\r?\n/).map(line => line.trim()).filter(Boolean);

  if (lines.length === 0) {
    throw new Error('Arquivo detection_ids.csv está vazio.');
  }

  const [header, ...rows] = lines;
  const detectionIds = rows
    .map(id => id.replace(/"/g, '').trim())
    .filter(id => id)
    .filter(id => /^\d+$/.test(id));

  if (detectionIds.length === 0) {
    throw new Error('Nenhum Detection ID válido encontrado no arquivo detection_ids.csv.');
  }

  return detectionIds;
};

const classifyWindow = (detection) => {
  const severity = Number(detection.severity) || 0;
  if (severity >= 4) return 'PRD_Alta';
  if (severity === 3) return 'PRD_Baixa';
  return 'DEV_QA';
};

const normalizeStatus = (status = '') => status.trim().toLowerCase();

const buildDetectionsCsv = (detections) => {
  const headers = ['hostIp', 'hostDns', 'hostTags', 'os', 'qid', 'severity', 'status', 'firstFound', 'lastFound', 'title', 'solution'];

  const escape = (value) => {
    const stringValue = value === undefined || value === null ? '' : String(value);
    if (/[",\n]/.test(stringValue)) {
      return `"${stringValue.replace(/"/g, '""')}"`;
    }
    return stringValue;
  };

  const rows = detections.map(detection => headers.map(header => escape(detection[header])).join(','));
  return [headers.join(','), ...rows].join('\n');
};

const buildDetectionsWorkbook = async (detections) => {
  const workbook = new ExcelJS.Workbook();
  const worksheet = workbook.addWorksheet('Detections');

  worksheet.columns = [
    { header: 'Host IP', key: 'hostIp', width: 15 },
    { header: 'Host DNS', key: 'hostDns', width: 30 },
    { header: 'Tags', key: 'hostTags', width: 30 },
    { header: 'OS', key: 'os', width: 30 },
    { header: 'QID', key: 'qid', width: 10 },
    { header: 'Severity', key: 'severity', width: 10 },
    { header: 'Status', key: 'status', width: 15 },
    { header: 'First Found', key: 'firstFound', width: 22 },
    { header: 'Last Found', key: 'lastFound', width: 22 },
    { header: 'Title', key: 'title', width: 50 },
    { header: 'Solution', key: 'solution', width: 80 }
  ];

  detections.forEach(detection => worksheet.addRow(detection));

  worksheet.getRow(1).font = { bold: true };
  worksheet.columns.forEach(column => {
    column.alignment = { wrapText: true };
  });

  return workbook;
};

const buildEffectivenessSummary = (detections) => {
  const summary = {
    DEV_QA: { total: 0, corrigidas: 0, pendentes: 0, efetividade: 0 },
    PRD_Baixa: { total: 0, corrigidas: 0, pendentes: 0, efetividade: 0 },
    PRD_Alta: { total: 0, corrigidas: 0, pendentes: 0, efetividade: 0 },
    total_geral: 0
  };

  detections.forEach(detection => {
    const window = classifyWindow(detection);
    if (!detectionWindows.includes(window)) return;

    summary[window].total++;
    summary.total_geral++;

    const normalizedStatus = normalizeStatus(detection.status);
    const isFixed = ['fixed', 'corrigida', 'corrigido'].includes(normalizedStatus);
    if (isFixed) {
      summary[window].corrigidas++;
    } else {
      summary[window].pendentes++;
    }
  });

  detectionWindows.forEach(window => {
    const windowData = summary[window];
    if (windowData.total > 0) {
      windowData.efetividade = Number((windowData.corrigidas / windowData.total).toFixed(2));
    }
  });

  return summary;
};

// ROTAS DA API

app.get('/api/health', (req, res) => {
  res.json({
    status: 'online',
    timestamp: new Date().toISOString(),
    qualysUrl: QUALYS_CONFIG.baseURL,
    version: '1.0.0',
    hasCredentials: !!(QUALYS_CONFIG.username && QUALYS_CONFIG.password)
  });
});

app.get('/api/hosts', auth, async (req, res) => {
  try {
    const { data: hosts, cached, stale } = await getCachedData(cache.hosts, () => qualysAPI.getHostList());

    res.json({
      success: true,
      total: hosts.length,
      cached,
      stale,
      data: hosts
    });
  } catch (error) {
    console.error('Erro em /api/hosts:', error.message);
    res.status(500).json({
      success: false,
      error: 'Erro ao buscar hosts',
      message: error.message
    });
  }
});

app.get('/api/vulnerabilities', auth, async (req, res) => {
  try {
    const { data: vulnerabilities, cached, stale } = await getCachedData(cache.vulnerabilities, () => qualysAPI.getVulnerabilities());

    res.json({
      success: true,
      total: vulnerabilities.length,
      cached,
      stale,
      data: vulnerabilities
    });
  } catch (error) {
    console.error('Erro em /api/vulnerabilities:', error.message);
    res.status(500).json({
      success: false,
      error: 'Erro ao buscar vulnerabilidades',
      message: error.message
    });
  }
});

app.get('/api/scans', auth, async (req, res) => {
  try {
    const scans = await qualysAPI.getScanList();
    res.json({
      success: true,
      total: scans.length,
      data: scans
    });
  } catch (error) {
    console.error('Erro em /api/scans:', error.message);
    res.status(500).json({
      success: false,
      error: 'Erro ao buscar scans',
      message: error.message
    });
  }
});

app.get('/api/dashboard/summary', auth, async (req, res) => {
  try {
    const [vulnResult, hostResult] = await Promise.all([
      getCachedData(cache.vulnerabilities, () => qualysAPI.getVulnerabilities()),
      getCachedData(cache.hosts, () => qualysAPI.getHostList())
    ]);

    const vulnerabilities = vulnResult?.data || [];
    const hosts = hostResult?.data || [];
    
    const severityCount = { '1': 0, '2': 0, '3': 0, '4': 0, '5': 0 };
    const qidCount = {};
    const statusCount = {};
    
    const tagDistribution = {
      DEV_QA: { critical: 0, high: 0, medium: 0, total: 0 },
      PRD_Baixa: { critical: 0, high: 0, medium: 0, total: 0 },
      PRD_Alta: { critical: 0, high: 0, medium: 0, total: 0 }
    };
    
    vulnerabilities.forEach(vuln => {
      const severity = vuln.severity || '0';
      if (severityCount[severity] !== undefined) {
        severityCount[severity]++;
      }
      
      const qid = vuln.qid || 'Unknown';
      qidCount[qid] = (qidCount[qid] || 0) + 1;
      
      const status = vuln.status || 'Unknown';
      statusCount[status] = (statusCount[status] || 0) + 1;
      
      if (vuln.hostTags && ['3', '4', '5'].includes(severity)) {
        const tags = vuln.hostTags.toUpperCase().replace(/\s/g, '_');
        
        if (tags.includes('DEV_QA')) {
          if (severity === '5') tagDistribution.DEV_QA.critical++;
          if (severity === '4') tagDistribution.DEV_QA.high++;
          if (severity === '3') tagDistribution.DEV_QA.medium++;
          tagDistribution.DEV_QA.total++;
        }
        
        if (tags.includes('PRD_BAIXA')) {
          if (severity === '5') tagDistribution.PRD_Baixa.critical++;
          if (severity === '4') tagDistribution.PRD_Baixa.high++;
          if (severity === '3') tagDistribution.PRD_Baixa.medium++;
          tagDistribution.PRD_Baixa.total++;
        }
        
        if (tags.includes('PRD_ALTA')) {
          if (severity === '5') tagDistribution.PRD_Alta.critical++;
          if (severity === '4') tagDistribution.PRD_Alta.high++;
          if (severity === '3') tagDistribution.PRD_Alta.medium++;
          tagDistribution.PRD_Alta.total++;
        }
      }
    });
    
    const topQids = Object.entries(qidCount)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([qid, count]) => ({ qid, count }));
    
    res.json({
      success: true,
      data: {
        totalHosts: hosts.length,
        totalVulnerabilities: vulnerabilities.length,
        severityDistribution: {
          critical: severityCount['5'],
          high: severityCount['4'],
          medium: severityCount['3'],
          low: severityCount['2'],
          info: severityCount['1']
        },
        statusDistribution: statusCount,
        topVulnerabilities: topQids,
        tagDistribution: tagDistribution,
        lastUpdated: new Date().toISOString()
      }
    });
  } catch (error) {
    console.error('Erro ao gerar resumo:', formatErrorMessage(error));
    res.status(500).json({
      success: false,
      error: 'Erro ao gerar resumo',
      message: formatErrorMessage(error)
    });
  }
});

app.get('/api/dashboard/trends', auth, async (req, res) => {
  try {
    const { data: vulnerabilities = [] } = await getCachedData(cache.vulnerabilities, () => qualysAPI.getVulnerabilities());
    
    const dateCount = {};
    vulnerabilities.forEach(vuln => {
      const firstFound = vuln.firstFound;
      if (firstFound) {
        const date = firstFound.split('T')[0];
        dateCount[date] = (dateCount[date] || 0) + 1;
      }
    });
    
    const trends = Object.entries(dateCount)
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([date, count]) => ({ date, count }));
    
    res.json({
      success: true,
      data: {
        trends,
        totalDays: trends.length
      }
    });
  } catch (error) {
    console.error('Erro em /api/dashboard/trends:', formatErrorMessage(error));
    res.status(500).json({
      success: false,
      error: 'Erro ao gerar tendencias',
      message: formatErrorMessage(error)
    });
  }
});

app.get('/api/export/vulnerabilities/excel', auth, async (req, res) => {
  try {
    const vulnerabilities = await qualysAPI.getVulnerabilities();
    
    if (vulnerabilities.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Nenhuma vulnerabilidade encontrada'
      });
    }
    
    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet('Vulnerabilidades');
    
    worksheet.columns = [
      { header: 'Detection ID', key: 'uniqueVulnId', width: 20 },
      { header: 'DNS', key: 'hostDns', width: 30 },
      { header: 'Host IP', key: 'hostIp', width: 15 },
      { header: 'Sistema Operacional', key: 'os', width: 25 },
      { header: 'Titulo', key: 'title', width: 40 },
      { header: 'Solucao', key: 'solution', width: 40 },
      { header: 'Resultados', key: 'results', width: 50 },
      { header: 'Severidade', key: 'severity', width: 12 },
      { header: 'Status', key: 'status', width: 12 },
      { header: 'QID', key: 'qid', width: 10 },
      { header: 'Porta', key: 'port', width: 10 },
      { header: 'Primeira Deteccao', key: 'firstFound', width: 20 }
    ];
    
    worksheet.getRow(1).font = { bold: true, color: { argb: 'FFFFFFFF' } };
    worksheet.getRow(1).fill = {
      type: 'pattern',
      pattern: 'solid',
      fgColor: { argb: 'FF4472C4' }
    };
    
    vulnerabilities.forEach(vuln => {
      worksheet.addRow(vuln);
    });
    
    worksheet.autoFilter = {
      from: 'A1',
      to: 'L1'
    };
    
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `qualys_vulnerabilities_${timestamp}.xlsx`;
    
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    
    await workbook.xlsx.write(res);
    res.end();
    
  } catch (error) {
    console.error('Erro em /api/export/excel:', error.message);
    res.status(500).json({
      success: false,
      error: 'Erro ao exportar Excel',
      message: error.message
    });
  }
});

app.get('/api/export/vulnerabilities/csv', auth, async (req, res) => {
  try {
    const vulnerabilities = await qualysAPI.getVulnerabilities();
    
    if (vulnerabilities.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Nenhuma vulnerabilidade encontrada'
      });
    }
    
    const headers = ['Detection ID', 'DNS', 'Host IP', 'Sistema Operacional', 'Titulo', 'Solucao', 'Resultados', 'Severidade', 'Status', 'QID', 'Porta', 'Primeira Deteccao'];
    
    let csv = headers.join(',') + '\n';
    
    vulnerabilities.forEach(vuln => {
      const row = [
        vuln.uniqueVulnId || vuln.detectionId,
        vuln.hostDns,
        vuln.hostIp,
        vuln.os || '',
        vuln.title || '',
        vuln.solution || '',
        vuln.results || '',
        vuln.severity,
        vuln.status,
        vuln.qid,
        vuln.port,
        vuln.firstFound
      ].map(field => `"${field || ''}"`);
      
      csv += row.join(',') + '\n';
    });
    
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `qualys_vulnerabilities_${timestamp}.csv`;
    
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(csv);
    
  } catch (error) {
    console.error('Erro em /api/export/csv:', error.message);
    res.status(500).json({
      success: false,
      error: 'Erro ao exportar CSV',
      message: error.message
    });
  }
});

app.get('/api/detections/enriched', auth, async (req, res) => {
  try {
    const { format } = req.query;
    const detections = await qualysAPI.getHostDetectionsWithDetails();

    if (format === 'csv') {
      const csvContent = buildDetectionsCsv(detections);
      res.header('Content-Type', 'text/csv');
      res.attachment('detections.csv');
      return res.send(csvContent);
    }

    if (format === 'xlsx') {
      const workbook = await buildDetectionsWorkbook(detections);
      res.header('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
      res.attachment('detections.xlsx');
      await workbook.xlsx.write(res);
      return res.end();
    }

    res.json({
      success: true,
      total: detections.length,
      data: detections
    });
  } catch (error) {
    console.error('Erro em /api/detections/enriched:', formatErrorMessage(error));
    res.status(500).json({
      success: false,
      error: 'Erro ao buscar detecções com detalhes',
      message: formatErrorMessage(error)
    });
  }
});

app.post('/efetividade/calcular', auth, async (req, res) => {
  try {
    const detectionIds = await readDetectionIdsFromCSV();

    const detectionPromises = detectionIds.map(async (id) => {
      try {
        return await qualysAPI.getDetectionById(id);
      } catch (error) {
        console.warn(`Falha ao consultar Detection ID ${id}:`, error.message);
        return null;
      }
    });

    const detections = (await Promise.all(detectionPromises)).filter(Boolean);

    if (detections.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Nenhum dado retornado pela API do Qualys para os Detection IDs fornecidos.'
      });
    }

    const summary = buildEffectivenessSummary(detections);

    return res.json({
      success: true,
      ...summary,
      detections
    });
  } catch (error) {
    console.error('Erro em /efetividade/calcular:', error.message);
    res.status(400).json({
      success: false,
      error: error.message || 'Erro ao calcular efetividade'
    });
  }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`\n🚀 API Qualys rodando na porta ${PORT}`);
  console.log(`📊 Dashboard: http://localhost:${PORT}`);
  console.log(`🔐 Credenciais da API Web: ${process.env.API_USERNAME || 'admin'} / ${process.env.API_PASSWORD || 'admin123'}`);
  console.log(`✅ Qualys conectado: ${QUALYS_CONFIG.username ? 'Sim' : 'Não'}\n`);
});