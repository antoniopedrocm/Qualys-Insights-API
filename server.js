const express = require('express');
const axios = require('axios');
const https = require('https');
const xml2js = require('xml2js');
const ExcelJS = require('exceljs');
const cors = require('cors');
const basicAuth = require('express-basic-auth');
const path = require('path');
const fs = require('fs');
const { parseDetectionIds, classifyDetectionIds } = require('./src/effectiveness');
const { normalizeSeverity } = require('./src/severity');
const { loadCache, upsertMany } = require('./src/cache/effectivenessCache');
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
  kb: {
    data: {},
    lastUpdate: null
  },
  ttl: 300000
};

const MAX_KB_CONCURRENCY = 3;
const KB_BATCH_SIZE = 30;

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

const isQualysQueueError = (error) => error?.name === 'QualysQueueError' || error?.code === '1960';

const sendQueueResponse = (res, error, payload = {}) => {
  const statusCode = 503;

  if (error?.retryAfterSeconds) {
    res.set('Retry-After', String(Math.max(1, Math.round(error.retryAfterSeconds))));
  }

  return res.status(statusCode).json({
    success: false,
    error: 'Qualys job ainda em execução',
    message: error?.message || 'O Qualys ainda está processando a consulta.',
    callsToFinish: error?.callsToFinish,
    retryAfterSeconds: error?.retryAfterSeconds,
    ...payload
  });
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
      return { data: cacheEntry.data, cached: true, stale: true, error };
    }
    throw error;
  }
};

const parseHostTags = (hostTags) => {
  if (Array.isArray(hostTags)) return hostTags.filter(Boolean);
  if (!hostTags) return [];
  return String(hostTags)
    .split(',')
    .map((tag) => tag.trim())
    .filter(Boolean);
};

const resolveLastSeen = (vuln, status, generatedAt, existingItem = null) => {
  const explicitLastSeen = vuln?.lastSeen || vuln?.lastFound || vuln?.lastDetected || vuln?.lastTest || null;
  if (explicitLastSeen) return explicitLastSeen;

  if (status === 'open') return generatedAt;
  if (status === 'fixed') return existingItem?.lastSeen || null;
  return null;
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
  async parseQueueError(xmlData) {
    if (!xmlData) return null;

    try {
      const parser = new xml2js.Parser({ explicitArray: false });
      const parsed = await parser.parseStringPromise(xmlData);
      const response = parsed?.SIMPLE_RETURN?.RESPONSE || parsed?.RESPONSE || parsed;

      const code = response?.CODE ? String(response.CODE) : undefined;
      const callsToFinishRaw = response?.CALLS_TO_FINISH || response?.CALL_TO_FINISH || response?.CALLS;
      const callsToFinish = callsToFinishRaw !== undefined ? Number(callsToFinishRaw) : undefined;
      const retryAfterSeconds = Number.isFinite(callsToFinish) ? callsToFinish * 30 : undefined;
      const message = response?.TEXT || response?.ERROR || 'Qualys job still running. Try again later.';

      return { code, callsToFinish, retryAfterSeconds, message };
    } catch (parseError) {
      console.warn('Não foi possível interpretar a resposta de fila do Qualys:', parseError.message);
      return null;
    }
  }

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
    const buildDetectionQuery = (truncationLimit) => ({
      action: 'list',
      truncation_limit: String(truncationLimit),
      status: 'New,Active,Re-Opened,Fixed',
      output_format: 'XML',
      show_tags: '1'
    });

    const hasFixedExclusion = (params = {}) => {
      const serialized = JSON.stringify(params).toLowerCase();
      return serialized.includes('exclude_fixed') || serialized.includes('excludedvulnerabilities') || serialized.includes('!=fixed');
    };

    try {
      const params = buildDetectionQuery(1000);
      console.log('[QualysAPI] Query host/vm/detection:', params);
      if (hasFixedExclusion(params)) {
        console.error('[QualysAPI] ERRO: Query contém exclusão de FIXED:', params);
      }
      const response = await qualysClient.get('/api/2.0/fo/asset/host/vm/detection/', {
        params,
        timeout: 120000
      });
      return await this.buildVulnerabilitiesFromXml(response.data);
    } catch (error) {
      const formattedError = formatErrorMessage(error);
      console.error('Erro ao obter vulnerabilidades (Tentativa 1):', formattedError);

      if (error.response?.status === 409) {
        const queueInfo = await this.parseQueueError(error.response?.data);

        if (queueInfo?.code === '1960') {
          const queueError = new Error(queueInfo.message || 'Qualys job ainda em execução');
          queueError.name = 'QualysQueueError';
          queueError.code = queueInfo.code;
          queueError.callsToFinish = queueInfo.callsToFinish;
          queueError.retryAfterSeconds = queueInfo.retryAfterSeconds;
          throw queueError;
        }

        console.log('Tentando com limite menor...');
        try {
          const params = buildDetectionQuery(500);
          console.log('[QualysAPI] Query host/vm/detection (retry):', params);
          if (hasFixedExclusion(params)) {
            console.error('[QualysAPI] ERRO: Query de retry contém exclusão de FIXED:', params);
          }
          const response = await qualysClient.get('/api/2.0/fo/asset/host/vm/detection/', {
            params,
            timeout: 120000
          });
          return await this.buildVulnerabilitiesFromXml(response.data);
        } catch (retryError) {
          console.error('Erro na segunda tentativa:', retryError.message);
          throw retryError;
        }
      }
      throw new Error(formattedError);
    }
  }

  async buildVulnerabilitiesFromXml(xmlData) {
    const parsedVulnerabilities = await this.parseVulnerabilityXML(xmlData);
    const uniqueQids = new Set(parsedVulnerabilities.map(vuln => vuln.qid).filter(Boolean));

    const now = Date.now();
    const kbCacheValid = cache.kb.lastUpdate && now - cache.kb.lastUpdate < cache.ttl;
    const cachedKbDetails = {};

    if (kbCacheValid) {
      uniqueQids.forEach(qid => {
        if (cache.kb.data[qid]) {
          cachedKbDetails[qid] = cache.kb.data[qid];
        }
      });
    }

    const missingQids = Array.from(uniqueQids).filter(qid => !cachedKbDetails[qid]);
    const fetchedKbDetails = missingQids.length ? await this.fetchKnowledgeBaseDetails(missingQids) : {};
    const kbDetails = { ...cachedKbDetails, ...fetchedKbDetails };

    return parsedVulnerabilities.map(vuln => {
      const kb = kbDetails[vuln.qid] || {};
      const detectionId = vuln.detectionId || '';
      const normalizedUniqueId = detectionId || vuln.uniqueVulnId || kb.uniqueVulnId || '';

      return {
        ...vuln,
        detectionId,
        uniqueVulnId: normalizedUniqueId,
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
        const detectionIdFromApi = detection.UNIQUE_VULN_ID || detection.VULN_INFO?.UNIQUE_VULN_ID || '';
        const detectionId = detectionIdFromApi;
        const uniqueVulnId = detectionIdFromApi;
        const detectionStatus = getDetectionStatusValue(detection);
        const isFixed = isDetectionFixed(detection);

        vulnerabilities.push({
          detectionId,
          uniqueVulnId,
          hostId,
          hostIp: ip,
          hostDns: dns,
          hostTags: hostTags,
          os,
          qid,
          type: detection.TYPE || '',
          severity: detection.SEVERITY || '',
          status: detectionStatus,
          detectionStatus,
          findingStatus: detection.FINDING_STATUS || '',
          state: detection.STATE || '',
          isFixed,
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
        uniqueVulnId: vuln.UNIQUE_VULN_ID || '',
        title: vuln.TITLE || '',
        solution: solutionValue || ''
      };
    });

    return details;
  }

  async fetchKnowledgeBaseDetails(qids, concurrency = MAX_KB_CONCURRENCY, batchSize = KB_BATCH_SIZE) {
    const qidArray = Array.from(qids);
    const results = {};
    const now = Date.now();

    const kbCacheValid = cache.kb.lastUpdate && now - cache.kb.lastUpdate < cache.ttl;
    if (!kbCacheValid) {
      cache.kb.data = {};
      cache.kb.lastUpdate = null;
    }

    qidArray.forEach(qid => {
      if (kbCacheValid && cache.kb.data[qid]) {
        results[qid] = cache.kb.data[qid];
      }
    });

    const missingQids = qidArray.filter(qid => !results[qid]);
    if (!missingQids.length) return results;

    const batches = [];
    for (let i = 0; i < missingQids.length; i += batchSize) {
      batches.push(missingQids.slice(i, i + batchSize));
    }

    for (let i = 0; i < batches.length; i += concurrency) {
      const batchGroup = batches.slice(i, i + concurrency);

      const responses = await Promise.all(batchGroup.map(async batch => {
        try {
          const response = await qualysClient.get('/api/2.0/fo/knowledge_base/vuln/', {
            params: {
              action: 'list',
              ids: batch.join(',')
            },
            timeout: 120000
          });

          const parsed = await this.parseKnowledgeBaseXML(response.data);
          return parsed;
        } catch (error) {
          console.warn(`Falha ao consultar QIDs ${batch.join(',')}:`, formatErrorMessage(error));
          return {};
        }
      }));

      responses.forEach(parsed => {
        Object.entries(parsed).forEach(([qid, details]) => {
          if (details) {
            results[qid] = details;
            cache.kb.data[qid] = details;
          }
        });
      });
    }

    cache.kb.lastUpdate = Date.now();
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
const detectionWindowLabels = {
  DEV_QA: 'Desenvolvimento e Qualidade',
  PRD_Baixa: 'Produção Baixa',
  PRD_Alta: 'Produção Alta'
};

const detectionWindowTagMatchers = {
  DEV_QA: ['DEV_QA', 'DESENVOLVIMENTO_E_QUALIDADE', 'DESENVOLVIMENTO', 'QUALIDADE'],
  PRD_Baixa: ['PRD_BAIXA', 'PRODUCAO_BAIXA', 'PRODUÇÃO_BAIXA'],
  PRD_Alta: ['PRD_ALTA', 'PRODUCAO_ALTA', 'PRODUÇÃO_ALTA']
};

const normalizeTagString = (tags = '') => String(tags)
  .toUpperCase()
  .replace(/\s+/g, '_')
  .replace(/\//g, '_');

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

  const normalizedLines = lines
    .map(id => id.replace(/"/g, '').trim())
    .filter(Boolean);

  const hasHeader = normalizedLines.length > 0 && !/^\d+$/.test(normalizedLines[0]);
  const candidates = hasHeader ? normalizedLines.slice(1) : normalizedLines;

  const detectionIds = candidates.filter(id => /^\d+$/.test(id));

  if (detectionIds.length === 0) {
    throw new Error('Nenhum Detection ID válido encontrado no arquivo detection_ids.csv.');
  }

  return detectionIds;
};

const classifyWindow = (detection = {}) => {
  const normalizedTags = normalizeTagString(detection.hostTags || detection.tags || '');

  const matchedWindow = detectionWindows.find(window =>
    detectionWindowTagMatchers[window].some(tag => normalizedTags.includes(tag))
  );

  return matchedWindow || null;
};

const normalizeStatus = (status = '') => status.trim().toLowerCase();

const getDetectionStatusValue = (item = {}) => {
  const statusCandidates = [
    item.status,
    item.STATUS,
    item.state,
    item.STATE,
    item.detectionStatus,
    item.DETECTION_STATUS,
    item.findingStatus,
    item.FINDING_STATUS
  ];

  const firstStatus = statusCandidates.find((value) => value !== undefined && value !== null && String(value).trim() !== '');

  if (firstStatus !== undefined) {
    return String(firstStatus).trim();
  }

  const isFixedCandidates = [item.isFixed, item.IS_FIXED, item.fixed, item.FIXED];
  const fixedCandidate = isFixedCandidates.find((value) => value !== undefined && value !== null);

  if (fixedCandidate !== undefined) {
    const normalized = String(fixedCandidate).trim().toLowerCase();
    if (['true', '1', 'yes', 'sim'].includes(normalized)) return 'Fixed';
    if (['false', '0', 'no', 'nao', 'não'].includes(normalized)) return 'Active';
    if (typeof fixedCandidate === 'boolean') return fixedCandidate ? 'Fixed' : 'Active';
  }

  return '';
};

const isDetectionFixed = (item = {}) => normalizeStatus(getDetectionStatusValue(item)) === 'fixed';

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
  const summary = detectionWindows.reduce((acc, window) => {
    acc[window] = {
      label: detectionWindowLabels[window],
      total: 0,
      corrigidas: 0,
      pendentes: 0,
      efetividade: 0
    };
    return acc;
  }, { total_geral: 0, windowLabels: { ...detectionWindowLabels } });

  detections.forEach(detection => {
    const window = classifyWindow(detection);
    if (!window || !detectionWindows.includes(window)) return;

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
    const vulnResult = await getCachedData(cache.vulnerabilities, () => qualysAPI.getVulnerabilities());
    const vulnerabilities = vulnResult?.data || [];
    const queueWarning = isQualysQueueError(vulnResult?.error);

    const totalFixed = vulnerabilities.filter((vuln) => isDetectionFixed(vuln) || vuln.isFixed === true).length;
    const totalOpen = vulnerabilities.length - totalFixed;
    console.log(`[QualysAPI] Contagem de vulnerabilidades -> total_fixed=${totalFixed}, total_open=${totalOpen}`);

    const responsePayload = {
      success: true,
      total: vulnerabilities.length,
      cached: vulnResult?.cached || false,
      stale: vulnResult?.stale || false,
      data: vulnerabilities
    };

    if (queueWarning) {
      return sendQueueResponse(res, vulnResult.error, responsePayload);
    }

    res.json(responsePayload);
  } catch (error) {
    if (isQualysQueueError(error)) {
      return sendQueueResponse(res, error);
    }

    const message = formatErrorMessage(error);
    console.error('Erro em /api/vulnerabilities:', message);
    res.status(502).json({
      success: false,
      error: 'Erro ao buscar vulnerabilidades',
      message
    });
  }
});

app.post('/api/effectiveness', auth, async (req, res) => {
  try {
    const inputDetectionIds = Array.isArray(req.body?.detectionIds)
      ? req.body.detectionIds
      : parseDetectionIds(String(req.body?.input || ''));

    if (!inputDetectionIds.length) {
      return res.status(400).json({
        success: false,
        error: 'Nenhum Detection ID informado.',
        message: 'Informe pelo menos um Detection ID para análise.'
      });
    }

    const uniqueIds = Array.from(new Set(inputDetectionIds.map((id) => String(id).trim()).filter(Boolean)));
    const vulnResult = await getCachedData(cache.vulnerabilities, () => qualysAPI.getVulnerabilities());
    const vulnerabilities = vulnResult?.data || [];
    const queueWarning = isQualysQueueError(vulnResult?.error);

    const vulnerabilitiesById = new Map();
    vulnerabilities.forEach((vuln) => {
      const detectionId = String(vuln.detectionId || vuln.uniqueVulnId || '').trim();
      if (detectionId && !vulnerabilitiesById.has(detectionId)) {
        vulnerabilitiesById.set(detectionId, vuln);
      }
    });

    const activeSet = new Set(
      Array.from(vulnerabilitiesById.entries())
        .filter(([, vuln]) => !isDetectionFixed(vuln) && vuln?.isFixed !== true)
        .map(([detectionId]) => detectionId)
    );
    const classified = classifyDetectionIds(uniqueIds, activeSet);
    const generatedAt = new Date().toISOString();
    const existingCache = await loadCache();

    const itemsToPersist = classified.items.map((item) => {
      const vuln = vulnerabilitiesById.get(item.detectionId);
      const existingItem = existingCache.itemsByDetectionId?.[item.detectionId] || null;

      if (item.status === 'invalid') {
        return {
          detectionId: item.detectionId,
          status: 'invalid',
          dns: existingItem?.dns || '',
          ip: existingItem?.ip || '',
          title: existingItem?.title || '',
          severity: existingItem?.severity || 'Info',
          solution: existingItem?.solution || '',
          hostTags: existingItem?.hostTags || [],
          lastSeen: null
        };
      }

      if (item.status === 'fixed') {
        return {
          detectionId: item.detectionId,
          status: 'fixed',
          dns: existingItem?.dns || vuln?.hostDns || '',
          ip: existingItem?.ip || vuln?.hostIp || '',
          title: existingItem?.title || vuln?.title || '',
          severity: existingItem?.severity || normalizeSeverity(vuln?.severity),
          solution: existingItem?.solution || vuln?.solution || '',
          hostTags: existingItem?.hostTags || parseHostTags(vuln?.hostTags),
          lastSeen: resolveLastSeen(vuln, 'fixed', generatedAt, existingItem)
        };
      }

      return {
        detectionId: item.detectionId,
        status: 'open',
        dns: vuln?.hostDns || existingItem?.dns || '',
        ip: vuln?.hostIp || existingItem?.ip || '',
        title: vuln?.title || existingItem?.title || '',
        severity: normalizeSeverity(vuln?.severity || existingItem?.severity),
        solution: vuln?.solution || existingItem?.solution || '',
        hostTags: parseHostTags(vuln?.hostTags || existingItem?.hostTags),
        lastSeen: resolveLastSeen(vuln, 'open', generatedAt, existingItem)
      };
    });

    const persistedCache = await upsertMany(itemsToPersist, { generatedAt });

    const payload = {
      success: true,
      total: classified.total,
      fixed: classified.fixed,
      open: classified.open,
      invalid: classified.invalid,
      cached: vulnResult?.cached || false,
      stale: vulnResult?.stale || false,
      filters: {
        severities: Array.from(new Set(itemsToPersist.map((item) => item.severity))).filter(Boolean),
        hostTags: Array.from(new Set(itemsToPersist.flatMap((item) => item.hostTags || []))).filter(Boolean)
      },
      items: classified.items.map((item) => persistedCache.itemsByDetectionId[item.detectionId] || {
        detectionId: item.detectionId,
        status: item.status,
        dns: '',
        ip: '',
        title: '',
        severity: 'Info',
        solution: '',
        hostTags: [],
        lastSeen: null
      })
    };

    if (queueWarning) {
      return sendQueueResponse(res, vulnResult.error, payload);
    }

    return res.json(payload);
  } catch (error) {
    if (isQualysQueueError(error)) {
      return sendQueueResponse(res, error);
    }

    const message = formatErrorMessage(error);
    console.error('Erro em /api/effectiveness:', message);
    return res.status(500).json({
      success: false,
      error: 'Erro ao calcular efetividade',
      message
    });
  }
});

app.get('/api/effectiveness/cache', auth, async (req, res) => {
  try {
    const cacheData = await loadCache();
    res.json({
      success: true,
      meta: cacheData.meta,
      items: Object.values(cacheData.itemsByDetectionId || {})
    });
  } catch (error) {
    const message = formatErrorMessage(error);
    res.status(500).json({
      success: false,
      error: 'Erro ao carregar cache de efetividade',
      message
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

    const queueWarning = isQualysQueueError(vulnResult?.error);

    const vulnerabilities = vulnResult?.data || [];
    const hosts = hostResult?.data || [];
    const relevantVulns = vulnerabilities.filter(vuln => ['3', '4', '5'].includes(String(vuln.severity)));
    
    const severityCount = { '1': 0, '2': 0, '3': 0, '4': 0, '5': 0 };
    const qidCount = {};
    const statusCount = {};
    
    const emptySeverityGroup = () => ({ abertas: 0, corrigidas: 0 });
    const tagDistribution = {
      DEV_QA: { critical: emptySeverityGroup(), high: emptySeverityGroup(), medium: emptySeverityGroup(), total: 0 },
      PRD_Baixa: { critical: emptySeverityGroup(), high: emptySeverityGroup(), medium: emptySeverityGroup(), total: 0 },
      PRD_Alta: { critical: emptySeverityGroup(), high: emptySeverityGroup(), medium: emptySeverityGroup(), total: 0 }
    };

    relevantVulns.forEach(vuln => {
      const severity = String(vuln.severity || '0').toUpperCase();
      const severityKey = severity === '5' || severity === 'CRITICAL'
        ? 'critical'
        : severity === '4' || severity === 'HIGH'
          ? 'high'
          : 'medium';

      const normalizedSeverity = severityKey === 'critical' ? '5' : severityKey === 'high' ? '4' : '3';
      severityCount[normalizedSeverity]++;

      const qid = vuln.qid || 'Unknown';
      qidCount[qid] = (qidCount[qid] || 0) + 1;

      const status = getDetectionStatusValue(vuln) || 'Unknown';
      statusCount[status] = (statusCount[status] || 0) + 1;

      if (vuln.hostTags && ['3', '4', '5', 'CRITICAL', 'HIGH', 'MEDIUM'].includes(severity)) {
        const tags = vuln.hostTags.toUpperCase().replace(/\s/g, '_');
        const statusBucket = isDetectionFixed(vuln) || vuln.isFixed === true ? 'corrigidas' : 'abertas';

        if (tags.includes('DEV_QA')) {
          tagDistribution.DEV_QA[severityKey][statusBucket]++;
          tagDistribution.DEV_QA.total++;
        }

        if (tags.includes('PRD_BAIXA')) {
          tagDistribution.PRD_Baixa[severityKey][statusBucket]++;
          tagDistribution.PRD_Baixa.total++;
        }

        if (tags.includes('PRD_ALTA')) {
          tagDistribution.PRD_Alta[severityKey][statusBucket]++;
          tagDistribution.PRD_Alta.total++;
        }
      }
    });
    
    const topQids = Object.entries(qidCount)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([qid, count]) => ({ qid, count }));
    
    const responsePayload = {
      success: true,
      cached: vulnResult?.cached || false,
      stale: vulnResult?.stale || false,
      data: {
        totalHosts: hosts.length,
        totalVulnerabilities: relevantVulns.length,
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
    };

    if (queueWarning) {
      return sendQueueResponse(res, vulnResult.error, {
        cached: responsePayload.cached,
        stale: responsePayload.stale,
        data: responsePayload.data
      });
    }

    res.json(responsePayload);
  } catch (error) {
    if (isQualysQueueError(error)) {
      return sendQueueResponse(res, error);
    }

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
    const vulnResult = await getCachedData(cache.vulnerabilities, () => qualysAPI.getVulnerabilities());
    const queueWarning = isQualysQueueError(vulnResult?.error);
    const relevantVulns = (vulnResult?.data || []).filter(vuln => ['3', '4', '5'].includes(String(vuln.severity)));

    const dateCount = {};
    relevantVulns.forEach(vuln => {
      const firstFound = vuln.firstFound;
      if (firstFound) {
        const date = firstFound.split('T')[0];
        dateCount[date] = (dateCount[date] || 0) + 1;
      }
    });
    
    const trends = Object.entries(dateCount)
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([date, count]) => ({ date, count }));
    
    const responsePayload = {
      success: true,
      cached: vulnResult?.cached || false,
      stale: vulnResult?.stale || false,
      data: {
        trends,
        totalDays: trends.length
      }
    };

    if (queueWarning) {
      return sendQueueResponse(res, vulnResult.error, {
        cached: responsePayload.cached,
        stale: responsePayload.stale,
        data: responsePayload.data
      });
    }

    res.json(responsePayload);
  } catch (error) {
    if (isQualysQueueError(error)) {
      return sendQueueResponse(res, error);
    }

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
      const detectionId = vuln.detectionId || vuln.uniqueVulnId || '';
      const row = [
        detectionId,
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
      return res.status(200).json({
        success: false,
        message: 'Nenhuma detecção foi retornada pela API do Qualys para os IDs informados. Verifique se os IDs estão disponíveis na sua conta ou se há dados recentes na plataforma.',
        attemptedDetectionIds: detectionIds,
        totalAttempted: detectionIds.length,
        detections: []
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
