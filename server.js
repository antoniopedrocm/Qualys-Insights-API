const express = require('express');
const axios = require('axios');
const https = require('https');
const xml2js = require('xml2js');
const ExcelJS = require('exceljs');
const cors = require('cors');
const basicAuth = require('express-basic-auth');
const path = require('path');
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
  vulnerabilities: null,
  hosts: null,
  lastUpdate: null,
  ttl: 300000
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
      return await this.parseVulnerabilityXML(response.data);
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
          return await this.parseVulnerabilityXML(response.data);
        } catch (retryError) {
          console.error('Erro na segunda tentativa:', retryError.message);
          throw retryError;
        }
      }
      throw error;
    }
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

  async parseVulnerabilityXML(xmlData) {
    const parser = new xml2js.Parser({ explicitArray: false });
    const result = await parser.parseStringPromise(xmlData);
    
    const vulnerabilities = [];
    const hostList = result?.HOST_LIST_VM_DETECTION_OUTPUT?.RESPONSE?.HOST_LIST?.HOST;
    
    if (!hostList) return vulnerabilities;
    
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
      
      const detections = host.DETECTION_LIST?.DETECTION;
      if (!detections) return;
      
      const detectionArray = Array.isArray(detections) ? detections : [detections];
      
      detectionArray.forEach(detection => {
        vulnerabilities.push({
          hostIp: ip,
          hostDns: dns,
          hostTags: hostTags,
          os,
          qid: detection.QID || '',
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
}

const qualysAPI = new QualysAPI();

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
    const now = Date.now();
    
    if (cache.hosts && cache.lastUpdate && (now - cache.lastUpdate) < cache.ttl) {
      return res.json({
        success: true,
        total: cache.hosts.length,
        cached: true,
        data: cache.hosts
      });
    }
    
    const hosts = await qualysAPI.getHostList();
    cache.hosts = hosts;
    cache.lastUpdate = now;
    
    res.json({
      success: true,
      total: hosts.length,
      cached: false,
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
    const now = Date.now();
    
    if (cache.vulnerabilities && cache.lastUpdate && (now - cache.lastUpdate) < cache.ttl) {
      return res.json({
        success: true,
        total: cache.vulnerabilities.length,
        cached: true,
        data: cache.vulnerabilities
      });
    }
    
    const vulnerabilities = await qualysAPI.getVulnerabilities();
    cache.vulnerabilities = vulnerabilities;
    cache.lastUpdate = now;
    
    res.json({
      success: true,
      total: vulnerabilities.length,
      cached: false,
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
    const [vulnerabilities, hosts] = await Promise.all([
      qualysAPI.getVulnerabilities(),
      qualysAPI.getHostList()
    ]);
    
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
    console.error('Erro ao gerar resumo:', error.message);
    res.status(500).json({
      success: false,
      error: 'Erro ao gerar resumo',
      message: error.message
    });
  }
});

app.get('/api/dashboard/trends', auth, async (req, res) => {
  try {
    const vulnerabilities = await qualysAPI.getVulnerabilities();
    
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
    console.error('Erro em /api/dashboard/trends:', error.message);
    res.status(500).json({
      success: false,
      error: 'Erro ao gerar tendencias',
      message: error.message
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
      { header: 'IP do Host', key: 'hostIp', width: 15 },
      { header: 'DNS do Host', key: 'hostDns', width: 30 },
      { header: 'Tags', key: 'hostTags', width: 20 },
      { header: 'QID', key: 'qid', width: 10 },
      { header: 'Sistema Operacional', key: 'os', width: 25 },
      { header: 'Titulo', key: 'title', width: 40 },
      { header: 'Severidade', key: 'severity', width: 12 },
      { header: 'Tipo', key: 'type', width: 15 },
      { header: 'Solucao', key: 'solution', width: 40 },
      { header: 'Status', key: 'status', width: 12 },
      { header: 'Porta', key: 'port', width: 10 },
      { header: 'Protocolo', key: 'protocol', width: 12 },
      { header: 'Primeira Deteccao', key: 'firstFound', width: 20 },
      { header: 'Ultima Deteccao', key: 'lastFound', width: 20 },
      { header: 'Resultados', key: 'results', width: 50 }
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
      to: 'O1'
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
    
    const headers = ['IP do Host', 'DNS do Host', 'Tags', 'QID', 'Sistema Operacional', 'Titulo', 'Severidade', 'Tipo', 'Solucao', 'Status', 'Porta', 'Protocolo', 'Primeira Deteccao', 'Ultima Deteccao', 'Resultados'];
    
    let csv = headers.join(',') + '\n';
    
    vulnerabilities.forEach(vuln => {
      const row = [
        vuln.hostIp,
        vuln.hostDns,
        vuln.hostTags || '',
        vuln.qid,
        vuln.os || '',
        vuln.title || '',
        vuln.severity,
        vuln.type,
        vuln.solution || '',
        vuln.status,
        vuln.port,
        vuln.protocol,
        vuln.firstFound,
        vuln.lastFound,
        vuln.results || ''
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

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`\n🚀 API Qualys rodando na porta ${PORT}`);
  console.log(`📊 Dashboard: http://localhost:${PORT}`);
  console.log(`🔐 Credenciais da API Web: ${process.env.API_USERNAME || 'admin'} / ${process.env.API_PASSWORD || 'admin123'}`);
  console.log(`✅ Qualys conectado: ${QUALYS_CONFIG.username ? 'Sim' : 'Não'}\n`);
});