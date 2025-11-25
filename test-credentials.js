const axios = require('axios');
const https = require('https');

// Teste com diferentes formas de passar a senha
const credentials = [
  { user: 'hyper3ap1', pass: '9Qn2ctF$a3oO5rb8' },
  { user: 'hyper3ap1', pass: '9Qn2ctF\\$a3oO5rb8' }, // Escape do $
];

async function testCredentials() {
  for (let i = 0; i < credentials.length; i++) {
    const cred = credentials[i];
    console.log(`\n🔐 Teste ${i + 1}: ${cred.user} / ${cred.pass}`);
    
    try {
      const client = axios.create({
        baseURL: 'https://qualysguard.qg3.apps.qualys.com',
        auth: {
          username: cred.user,
          password: cred.pass
        },
        headers: {
          'X-Requested-With': 'API'
        },
        httpsAgent: new https.Agent({  
          rejectUnauthorized: false
        })
      });

      const response = await client.get('/api/2.0/fo/asset/host/', {
        params: { action: 'list', truncation_limit: '1' }
      });
      
      console.log('✅ SUCESSO! Status:', response.status);
      console.log('Essa é a credencial correta!');
      break;
      
    } catch (error) {
      console.log('❌ Falhou:', error.response?.data || error.message);
    }
  }
}

testCredentials();