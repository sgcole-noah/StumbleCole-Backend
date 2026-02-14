// UserIdCounter.js - Sistema de IDs sequenciais a partir de 500
const fs = require('fs');
const path = require('path');
const Console = require('./ConsoleUtils');

const COUNTER_FILE = path.join(__dirname, 'user_id_counter.json');
const STARTING_ID = 500;

class UserIdCounter {
  constructor() {
    this.currentId = STARTING_ID;
    this.loadCounter();
  }

  /**
   * Carrega o contador do arquivo
   */
  loadCounter() {
    try {
      if (fs.existsSync(COUNTER_FILE)) {
        const data = JSON.parse(fs.readFileSync(COUNTER_FILE, 'utf8'));
        this.currentId = data.currentId || STARTING_ID;
        Console.log('[UserIdCounter]', `Contador carregado: próximo ID será ${this.currentId}`);
      } else {
        Console.log('[UserIdCounter]', `Arquivo não existe, iniciando do ID ${STARTING_ID}`);
        this.saveCounter();
      }
    } catch (err) {
      Console.error('[UserIdCounter]', `Erro ao carregar contador: ${err.message}`);
      this.currentId = STARTING_ID;
    }
  }

  /**
   * Salva o contador no arquivo
   */
  saveCounter() {
    try {
      const data = {
        currentId: this.currentId,
        lastUpdate: new Date().toISOString()
      };
      fs.writeFileSync(COUNTER_FILE, JSON.stringify(data, null, 2));
    } catch (err) {
      Console.error('[UserIdCounter]', `Erro ao salvar contador: ${err.message}`);
    }
  }

  /**
   * Obtém o próximo ID disponível e incrementa o contador
   */
  getNextId() {
    const id = this.currentId;
    this.currentId++;
    this.saveCounter();
    Console.log('[UserIdCounter]', `ID ${id} atribuído. Próximo será ${this.currentId}`);
    return id;
  }

  /**
   * Obtém o ID atual sem incrementar
   */
  getCurrentId() {
    return this.currentId;
  }

  /**
   * Define manualmente o próximo ID (use com cuidado!)
   */
  setNextId(id) {
    if (id < STARTING_ID) {
      Console.warn('[UserIdCounter]', `Tentativa de definir ID menor que ${STARTING_ID}, ignorando`);
      return false;
    }
    this.currentId = id;
    this.saveCounter();
    Console.log('[UserIdCounter]', `Próximo ID definido manualmente para ${id}`);
    return true;
  }

  /**
   * Reseta o contador (use apenas para testes!)
   */
  reset() {
    this.currentId = STARTING_ID;
    this.saveCounter();
    Console.warn('[UserIdCounter]', `Contador resetado para ${STARTING_ID}`);
  }
}

// Exporta uma instância única (singleton)
module.exports = new UserIdCounter();
