const Console = require('./ConsoleUtils');

class TourXManager {
  constructor() {
    this.tourXData = {
      id: 'tourx_sgcole',
      name: '.gg/sgcole',
      type: '1v1',
      gameMode: 'Block Dash',
      status: 'active',
      createdAt: Date.now(),
      players: new Map(), // userId -> playerData
      matches: [],
      config: {
        maxPlayers: 2,
        minPlayers: 2,
        autoStart: true,
        matchDuration: 300000, // 5 minutos
        rewardMultiplier: 1.5
      }
    };
  }

  /**
   * Registra um jogador automaticamente no TourX quando faz login
   */
  autoRegisterPlayer(userId, username, stumbleId) {
    try {
      if (this.tourXData.players.has(userId)) {
        Console.log('TourX', `Jogador ${username} já registrado no TourX`);
        return { success: true, alreadyRegistered: true };
      }

      const playerData = {
        userId,
        username,
        stumbleId,
        registeredAt: Date.now(),
        wins: 0,
        losses: 0,
        status: 'waiting'
      };

      this.tourXData.players.set(userId, playerData);
      
      Console.log('TourX', `Jogador ${username} registrado automaticamente no TourX .gg/sgcole`);
      
      // Tentar criar match se houver 2 jogadores
      this.tryCreateMatch();
      
      return { success: true, registered: true };
    } catch (err) {
      Console.error('TourX', `Erro ao registrar jogador: ${err.message}`);
      return { success: false, error: err.message };
    }
  }

  /**
   * Tenta criar um match se houver 2 jogadores esperando
   */
  tryCreateMatch() {
    const waitingPlayers = Array.from(this.tourXData.players.values())
      .filter(p => p.status === 'waiting');

    if (waitingPlayers.length >= 2) {
      const player1 = waitingPlayers[0];
      const player2 = waitingPlayers[1];

      const matchId = `match_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      const roomCode = this.generateRoomCode();

      const match = {
        id: matchId,
        roomCode,
        player1: {
          userId: player1.userId,
          username: player1.username,
          stumbleId: player1.stumbleId
        },
        player2: {
          userId: player2.userId,
          username: player2.username,
          stumbleId: player2.stumbleId
        },
        status: 'waiting_start',
        createdAt: Date.now(),
        startedAt: null,
        finishedAt: null,
        winner: null
      };

      this.tourXData.matches.push(match);
      
      // Atualizar status dos jogadores
      player1.status = 'in_match';
      player2.status = 'in_match';

      Console.log('TourX', `Match criado: ${player1.username} vs ${player2.username}`);
      Console.log('TourX', `Código da sala: ${roomCode}`);

      return match;
    }

    return null;
  }

  /**
   * Gera um código de sala aleatório
   */
  generateRoomCode() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let code = '';
    for (let i = 0; i < 6; i++) {
      code += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return code;
  }

  /**
   * Reporta o vencedor de um match
   */
  reportWinner(matchId, winnerUserId) {
    try {
      const match = this.tourXData.matches.find(m => m.id === matchId);
      
      if (!match) {
        return { success: false, error: 'Match não encontrado' };
      }

      if (match.status === 'finished') {
        return { success: false, error: 'Match já foi finalizado' };
      }

      const winner = this.tourXData.players.get(winnerUserId);
      const loser = match.player1.userId === winnerUserId ? match.player2 : match.player1;
      const loserData = this.tourXData.players.get(loser.userId);

      if (!winner || !loserData) {
        return { success: false, error: 'Jogador não encontrado' };
      }

      // Atualizar estatísticas
      winner.wins++;
      loserData.losses++;
      winner.status = 'waiting';
      loserData.status = 'waiting';

      // Finalizar match
      match.status = 'finished';
      match.finishedAt = Date.now();
      match.winner = {
        userId: winnerUserId,
        username: winner.username
      };

      Console.log('TourX', `Match finalizado: ${winner.username} venceu contra ${loserData.username}`);

      // Tentar criar novo match
      this.tryCreateMatch();

      return { success: true, match };
    } catch (err) {
      Console.error('TourX', `Erro ao reportar vencedor: ${err.message}`);
      return { success: false, error: err.message };
    }
  }

  /**
   * Obtém dados do TourX ativo
   */
  getActiveTourX() {
    const waitingPlayers = Array.from(this.tourXData.players.values())
      .filter(p => p.status === 'waiting');

    const activeMatches = this.tourXData.matches.filter(m => m.status !== 'finished');

    return {
      id: this.tourXData.id,
      name: this.tourXData.name,
      type: this.tourXData.type,
      gameMode: this.tourXData.gameMode,
      status: this.tourXData.status,
      waitingPlayers: waitingPlayers.length,
      activeMatches: activeMatches.length,
      totalPlayers: this.tourXData.players.size,
      config: this.tourXData.config
    };
  }

  /**
   * Obtém matches ativos
   */
  getActiveMatches() {
    return this.tourXData.matches.filter(m => m.status !== 'finished');
  }

  /**
   * Obtém estatísticas de um jogador
   */
  getPlayerStats(userId) {
    const player = this.tourXData.players.get(userId);
    
    if (!player) {
      return null;
    }

    return {
      userId: player.userId,
      username: player.username,
      wins: player.wins,
      losses: player.losses,
      winRate: player.wins + player.losses > 0 
        ? ((player.wins / (player.wins + player.losses)) * 100).toFixed(2) + '%'
        : '0%',
      registeredAt: new Date(player.registeredAt).toISOString()
    };
  }

  /**
   * Obtém ranking do TourX
   */
  getRanking(limit = 10) {
    const players = Array.from(this.tourXData.players.values())
      .sort((a, b) => b.wins - a.wins)
      .slice(0, limit);

    return players.map((p, index) => ({
      rank: index + 1,
      username: p.username,
      wins: p.wins,
      losses: p.losses,
      winRate: p.wins + p.losses > 0 
        ? ((p.wins / (p.wins + p.losses)) * 100).toFixed(2) + '%'
        : '0%'
    }));
  }
}

module.exports = new TourXManager();

