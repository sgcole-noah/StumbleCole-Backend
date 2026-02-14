const Console = require('./ConsoleUtils');
const fs = require('fs').promises;
const path = require('path');

class TournamentManager {
  constructor() {
    this.tournaments = new Map();
    this.playerLinks = new Map(); // Map de deviceId -> discordId
    this.dataPath = path.join(__dirname, 'tournament-data.json');
    this.loadData();
  }

  async loadData() {
    try {
      const data = await fs.readFile(this.dataPath, 'utf8');
      const parsed = JSON.parse(data);
      this.tournaments = new Map(parsed.tournaments || []);
      this.playerLinks = new Map(parsed.playerLinks || []);
    } catch (err) {
      // Arquivo não existe, iniciar limpo
    }
  }

  async saveData() {
    try {
      const data = {
        tournaments: Array.from(this.tournaments.entries()),
        playerLinks: Array.from(this.playerLinks.entries())
      };
      await fs.writeFile(this.dataPath, JSON.stringify(data, null, 2));
    } catch (err) {
      Console.error('Tournament', `Erro ao salvar dados: ${err.message}`);
    }
  }

  createTournament(config) {
    const id = `tournament_${Date.now()}`;
    
    // Processar horários
    let registrationOpenTime = null;
    let startTime = null;
    let initialStatus = 'waiting'; // Padrão é waiting
    
    if (config.registrationTime && config.registrationTime !== 'Agora') {
      registrationOpenTime = this.parseTime(config.registrationTime);
      // Se parseTime retornou null (horário já passou), deixa como waiting
      // Se retornou timestamp futuro, status é scheduled
      if (registrationOpenTime && registrationOpenTime > Date.now()) {
        initialStatus = 'scheduled';
      }
    }
    
    if (config.startTime && config.startTime !== 'Imediato') {
      startTime = this.parseTime(config.startTime);
    }
    
    const tournament = {
      id,
      name: config.name || 'Torneio',
      style: config.style,
      emojis: config.emojis,
      map: config.map,
      maxPlayers: config.maxPlayers || 4,
      rounds: config.rounds || 2,
      startTime: config.startTime || 'Imediato',
      registrationTime: config.registrationTime || 'Agora',
      registrationOpenTime, // timestamp ou null
      tournamentStartTime: startTime, // timestamp ou null
      status: initialStatus,
      players: [],
      matches: [],
      currentRound: 0,
      createdAt: Date.now(),
      createdBy: config.createdBy
    };

    this.tournaments.set(id, tournament);
    this.saveData();
    Console.log('Tournament', `Torneio criado: ${id} (status: ${initialStatus})`);
    
    // Agendar abertura de inscrições apenas se for futuro
    if (registrationOpenTime && registrationOpenTime > Date.now()) {
      this.scheduleRegistrationOpen(id, registrationOpenTime);
    }
    
    // Agendar início do torneio apenas se for futuro
    if (startTime && startTime > Date.now()) {
      this.scheduleTournamentStart(id, startTime);
    }
    
    return tournament;
  }

  parseTime(timeStr) {
    // Formato: "HH:MM"
    const [hours, minutes] = timeStr.split(':').map(Number);
    const now = new Date();
    const scheduled = new Date(now.getFullYear(), now.getMonth(), now.getDate(), hours, minutes, 0);
    
    // Se o horário já passou hoje, retornar null para abrir imediatamente
    if (scheduled < now) {
      return null;
    }
    
    return scheduled.getTime();
  }

  scheduleRegistrationOpen(tournamentId, openTime) {
    const delay = openTime - Date.now();
    if (delay > 0) {
      setTimeout(() => {
        const tournament = this.tournaments.get(tournamentId);
        if (tournament && tournament.status === 'scheduled') {
          tournament.status = 'waiting';
          this.saveData();
          Console.log('Tournament', `Inscrições abertas para: ${tournamentId}`);
        }
      }, delay);
    }
  }

  scheduleTournamentStart(tournamentId, startTime) {
    const delay = startTime - Date.now();
    if (delay > 0) {
      setTimeout(() => {
        const tournament = this.tournaments.get(tournamentId);
        if (tournament && (tournament.status === 'waiting' || tournament.status === 'scheduled') && tournament.players.length >= 2) {
          Console.log('Tournament', `Iniciando torneio ${tournamentId}`);
          this.startTournament(tournamentId);
        } else if (tournament && tournament.players.length < 2) {
          tournament.status = 'cancelled';
          this.saveData();
        }
      }, delay);
    }
  }

  linkPlayer(userId, deviceId, username) {
    this.playerLinks.set(userId, { userId, deviceId, username, linkedAt: Date.now() });
    this.saveData();
    return true;
  }

  getPlayerLink(userId) {
    return this.playerLinks.get(userId);
  }

  getPlayerLinkByUserId(userId) {
    return this.playerLinks.get(userId);
  }

  registerPlayer(tournamentId, userId) {
    const tournament = this.tournaments.get(tournamentId);
    if (!tournament) return { error: 'Torneio não encontrado' };
    
    // Verificar se as inscrições estão abertas
    if (tournament.status === 'scheduled') {
      const timeLeft = tournament.registrationOpenTime - Date.now();
      const minutesLeft = Math.ceil(timeLeft / 60000);
      return { error: `Inscrições abrem em ${minutesLeft} minutos (${tournament.registrationTime})` };
    }
    
    if (tournament.status !== 'waiting') {
      return { error: 'Torneio já iniciado ou finalizado' };
    }

    if (tournament.players.length >= tournament.maxPlayers) {
      return { error: 'Torneio cheio' };
    }

    if (tournament.players.find(p => p.userId === userId)) {
      return { error: 'Você já está inscrito' };
    }

    const playerLink = this.playerLinks.get(userId);
    if (!playerLink) {
      return { error: 'Você precisa vincular seu ID primeiro' };
    }

    tournament.players.push({
      userId,
      deviceId: playerLink.deviceId,
      username: playerLink.username,
      registeredAt: Date.now(),
      wins: 0,
      eliminated: false
    });

    Console.log('Tournament', `Jogador ${playerLink.username} inscrito no torneio ${tournamentId}`);

    // NÃO iniciar automaticamente quando encher
    // Apenas aguardar o horário de início
    if (tournament.players.length === tournament.maxPlayers) {
      Console.log('Tournament', `Torneio ${tournamentId} cheio. Aguardando horário: ${tournament.startTime}`);
    }

    this.saveData();
    return { success: true, tournament };
  }

  deleteTournament(tournamentId) {
    const tournament = this.tournaments.get(tournamentId);
    if (!tournament) return { error: 'Torneio não encontrado' };
    
    this.tournaments.delete(tournamentId);
    this.saveData();
    return { success: true };
  }

  startTournament(tournamentId) {
    const tournament = this.tournaments.get(tournamentId);
    if (!tournament) return;

    // Verificar se é hora de começar
    if (tournament.tournamentStartTime && Date.now() < tournament.tournamentStartTime) {
      Console.log('Tournament', `Torneio ${tournamentId} ainda não está na hora de começar`);
      return;
    }

    tournament.status = 'in_progress';
    tournament.currentRound = 1;

    // Criar matches do primeiro round
    this.createMatches(tournamentId);
    
    Console.log('Tournament', `Torneio ${tournamentId} iniciado!`);
    this.saveData();
  }

  createMatches(tournamentId) {
    const tournament = this.tournaments.get(tournamentId);
    if (!tournament) return;

    const activePlayers = tournament.players.filter(p => !p.eliminated);
    const matches = [];

    // Criar pares de jogadores
    for (let i = 0; i < activePlayers.length; i += 2) {
      if (i + 1 < activePlayers.length) {
        const matchId = `match_${Date.now()}_${i}`;
        const roomCode = this.generateRoomCode();
        
        const match = {
          id: matchId,
          round: tournament.currentRound,
          players: [activePlayers[i], activePlayers[i + 1]],
          roomCode,
          status: 'waiting',
          winner: null,
          createdAt: Date.now(),
          tournamentId: tournament.id,
          tournamentName: tournament.name,
          map: tournament.map,
          style: tournament.style,
          emojis: tournament.emojis
        };
        
        matches.push(match);
        Console.log('Tournament', `Match: ${activePlayers[i].username} vs ${activePlayers[i + 1].username} - Código: ${roomCode}`);
      }
    }

    tournament.matches.push(...matches);
    this.saveData();
    return matches;
  }

  generateRoomCode() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let code = '';
    for (let i = 0; i < 6; i++) {
      code += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return code;
  }

  reportWinner(tournamentId, matchId, winnerDeviceId) {
    const tournament = this.tournaments.get(tournamentId);
    if (!tournament) return { error: 'Torneio não encontrado' };

    const match = tournament.matches.find(m => m.id === matchId);
    if (!match) return { error: 'Partida não encontrada' };

    if (match.status === 'finished') {
      return { error: 'Partida já finalizada' };
    }

    const winner = match.players.find(p => p.deviceId === winnerDeviceId);
    if (!winner) return { error: 'Jogador não está nesta partida' };

    match.status = 'finished';
    match.winner = winner;
    match.finishedAt = Date.now();

    // Atualizar wins do jogador
    const player = tournament.players.find(p => p.deviceId === winnerDeviceId);
    if (player) player.wins++;

    // Eliminar perdedor
    const loser = match.players.find(p => p.deviceId !== winnerDeviceId);
    if (loser) {
      const loserPlayer = tournament.players.find(p => p.deviceId === loser.deviceId);
      if (loserPlayer) loserPlayer.eliminated = true;
    }

    // Verificar se o round acabou
    const roundMatches = tournament.matches.filter(m => m.round === tournament.currentRound);
    const allFinished = roundMatches.every(m => m.status === 'finished');

    if (allFinished) {
      this.advanceRound(tournamentId);
    }

    this.saveData();
    return { success: true, match, tournament };
  }

  advanceRound(tournamentId) {
    const tournament = this.tournaments.get(tournamentId);
    if (!tournament) return;

    const activePlayers = tournament.players.filter(p => !p.eliminated);

    if (activePlayers.length === 1) {
      // Temos um campeão!
      tournament.status = 'finished';
      tournament.winner = activePlayers[0];
      tournament.finishedAt = Date.now();
      Console.log('Tournament', `Campeão: ${activePlayers[0].username}`);
    } else if (activePlayers.length > 1) {
      // Avançar para próximo round
      tournament.currentRound++;
      this.createMatches(tournamentId);
    }

    this.saveData();
  }

  getTournament(tournamentId) {
    return this.tournaments.get(tournamentId);
  }

  getActiveTournaments() {
    return Array.from(this.tournaments.values())
      .filter(t => t.status === 'scheduled' || t.status === 'waiting' || t.status === 'in_progress');
  }

  getAllTournaments() {
    return Array.from(this.tournaments.values());
  }

  getPlayerMatches(userId) {
    const matches = [];
    
    for (const tournament of this.tournaments.values()) {
      const playerMatches = tournament.matches.filter(m => 
        m.players.some(p => p.userId === userId) && m.status === 'waiting'
      );
      
      matches.push(...playerMatches.map(m => ({
        ...m,
        tournamentId: m.tournamentId || tournament.id,
        tournamentName: m.tournamentName || tournament.name,
        map: m.map || tournament.map,
        style: m.style || tournament.style,
        emojis: m.emojis || tournament.emojis
      })));
    }

    return matches;
  }
}

module.exports = new TournamentManager();
