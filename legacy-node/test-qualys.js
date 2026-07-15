const axios = require('axios');
const https = require('https');

const qualysClient = axios.create({
  baseURL: 'https://qualysguard.qg3.apps.qualys.com',
  auth: {
    username: 'hyper3ap1',
    password: '9Qn2ctF$a3oO5rb8'
  },
  headers: {
    'X-Requested-With': 'API'
  },
  httpsAgent: new https.Agent({  
    rejectUnauthorized: true
  })
});

async function testAPI() {
  try {
    console.log('🔍 Testando conexão com Qualys...\n');
    
    // Teste 1: Health Check
    console.log('1️⃣ Testando endpoint de hosts...');
    const hostsResponse = await qualysClient.get('/api/2.0/fo/asset/host/', {
      params: { action: 'list', truncation_limit: '10' }
    });
    console.log('✅ Status:', hostsResponse.status);
    console.log('📄 Resposta (primeiros 500 caracteres):', hostsResponse.data.substring(0, 500));
    
    console.log('\n2️⃣ Testando endpoint de vulnerabilidades...');
    const vulnResponse = await qualysClient.get('/api/2.0/fo/asset/host/vm/detection/', {
      params: {
        action: 'list',
        truncation_limit: '10',
        status: 'New,Active,Re-Opened'
      }
    });
    console.log('✅ Status:', vulnResponse.status);
    console.log('📄 Resposta (primeiros 500 caracteres):', vulnResponse.data.substring(0, 500));
    
    console.log('\n✅ Testes concluídos com sucesso!');
    
  } catch (error) {
    console.error('❌ Erro:', error.message);
    if (error.response) {
      console.error('Status:', error.response.status);
      console.error('Dados:', error.response.data);
    }
  }
}

testAPI();