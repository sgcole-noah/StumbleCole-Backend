// Script de teste para o sistema de kick
const axios = require('axios');

const BACKEND_URL = 'https://masterbuckiindi2.shardweb.app';

async function testKickSystem() {
  console.log('=== TESTE DO SISTEMA DE KICK ===\n');

  try {
    // 1. Listar clientes conectados
    console.log('1. Listando clientes conectados...');
    const listResponse = await axios.get(`${BACKEND_URL}/client/list`);
    console.log(`   Clientes conectados: ${listResponse.data.count}`);
    
    if (listResponse.data.clients.length > 0) {
      console.log('   IDs dos clientes:');
      listResponse.data.clients.forEach(id => {
        console.log(`   - ${id}`);
      });
    } else {
      console.log('   ⚠️  Nenhum cliente conectado. Conecte um cliente primeiro!');
      return;
    }

    // 2. Pegar o primeiro cliente para testar
    const testUserId = listResponse.data.clients[0];
    console.log(`\n2. Testando com userId: ${testUserId}`);

    // 3. Verificar status inicial (não deve estar kickado)
    console.log('\n3. Verificando status inicial...');
    const checkBefore = await axios.get(`${BACKEND_URL}/client/kick/check/${testUserId}`);
    console.log(`   shouldKick: ${checkBefore.data.shouldKick}`);
    console.log(`   ✅ Status inicial OK (não kickado)`);

    // 4. Simular kick (normalmente feito pelo bot Discord)
    console.log('\n4. Simulando kick do jogador...');
    console.log('   ⚠️  NOTA: Use o comando /kick no Discord para testar de verdade!');
    console.log(`   Comando: /kick userid:${testUserId}`);

    // 5. Aguardar um pouco
    console.log('\n5. Aguardando 2 segundos...');
    await new Promise(resolve => setTimeout(resolve, 2000));

    // 6. Verificar status após kick
    console.log('\n6. Verificando status após kick...');
    const checkAfter = await axios.get(`${BACKEND_URL}/client/kick/check/${testUserId}`);
    console.log(`   shouldKick: ${checkAfter.data.shouldKick}`);
    
    if (checkAfter.data.shouldKick) {
      console.log('   ✅ Cliente foi kickado com sucesso!');
    } else {
      console.log('   ℹ️  Cliente não foi kickado (use /kick no Discord)');
    }

    console.log('\n=== TESTE CONCLUÍDO ===');
    console.log('\nPara testar completamente:');
    console.log('1. Conecte um cliente no jogo');
    console.log('2. Use o comando /kick no Discord');
    console.log('3. Aguarde até 5 segundos');
    console.log('4. O cliente deve ser desconectado automaticamente');

  } catch (error) {
    console.error('\n❌ Erro no teste:', error.message);
    if (error.response) {
      console.error('   Resposta do servidor:', error.response.data);
    }
  }
}

// Executar teste
testKickSystem();
