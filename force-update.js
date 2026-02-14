// force-update.js - Script para forçar atualização do usuário
require('dotenv').config();
const axios = require('axios');

async function forceUpdate() {
  try {
    console.log('🔄 Forçando atualização do usuário 501...\n');

    // 1. Obter informações do usuário
    console.log('1️⃣ Obtendo informações do usuário...');
    const userResponse = await axios.get('http://localhost:80/bot/user/501', {
      headers: {
        'X-Bot-API-Key': process.env.BOT_API_KEY
      }
    });

    console.log('✅ Usuário encontrado:');
    console.log(`   ID: ${userResponse.data.user.id}`);
    console.log(`   Username: ${userResponse.data.user.username}`);
    console.log(`   Status: ${userResponse.data.user.isBanned ? '🚫 Banido' : '✅ Ativo'}`);

    // 2. Verificar se é sgzone
    if (userResponse.data.user.username.includes('sgzone')) {
      console.log('\n✅ Username já está com .gg/sgzone!');
      console.log('\n💡 Se ainda vê .gg/sgmasters no jogo:');
      console.log('   1. Faça logout do jogo');
      console.log('   2. Limpe o cache do jogo');
      console.log('   3. Faça login novamente');
    } else {
      console.log('\n❌ Username ainda está com .gg/sgmasters');
      console.log('   Atualizando...');

      // Atualizar para sgzone
      const updateResponse = await axios.post('http://localhost:80/user/updateusername', {
        Username: '.gg/sgzone<#ffff00><sup>501</sup>'
      }, {
        headers: {
          'Authorization': JSON.stringify({
            DeviceId: userResponse.data.user.deviceId,
            StumbleId: userResponse.data.user.stumbleId
          })
        }
      });

      console.log('✅ Username atualizado!');
      console.log(`   Novo username: ${updateResponse.data.User.username}`);
    }

  } catch (err) {
    console.error('❌ Erro:', err.response?.data || err.message);
  }
}

forceUpdate();
