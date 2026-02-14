require("dotenv").config();
const express = require("express");
const Console = require("./ConsoleUtils");
const CryptoUtils = require("./CryptoUtils");
const SharedUtils = require("./SharedUtils");
const BotManager = require("./BotManager");
const BotController = require("./BotController");
const TournamentManager = require("./TournamentManager");
const TourXManager = require("./TourXManager");
const { checkMaintenance } = require("./MaintenanceMiddleware");
const { 
  validateUsernameMiddleware
} = require("./AntiCheatMiddleware");

const {
  BackendUtils,
  UserModel,
  UserController,
  RoundController,
  BattlePassController,
  EconomyController,
  AnalyticsController,
  FriendsController,
  NewsController,
  MissionsController,
  TournamentXController,
  MatchmakingController,
  TournamentController,
  SocialController,
  EventsController,
  authenticate,
  errorControll,
  sendShared,
  OnlineCheck,
  VerifyPhoton
} = require("./BackendUtils");

const app = express();
const Title = "Bz Tours Backend " + process.env.version;
const PORT = process.env.PORT || 80;

app.use(express.json());
app.use(checkMaintenance);

// ===== ROTAS DO SISTEMA DE TORNEIOS (SEM AUTENTICAÇÃO) =====

// Servir página de torneios
app.get('/torneios-preview', (req, res) => {
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.sendFile(__dirname + '/public/torneios-preview/index.html');
});

// Servir arquivos estáticos da pasta torneios-preview
app.use('/torneios-preview', (req, res, next) => {
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  next();
}, express.static('public/torneios-preview'));

// Buscar usuário por ID do MongoDB
app.get('/tournament/user/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const user = await UserModel.findById(userId);
    
    if (!user) {
      return res.json({ success: false, error: 'Usuário não encontrado' });
    }

    res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        deviceId: user.deviceId,
        stumbleId: user.stumbleId
      }
    });
  } catch (err) {
    Console.error('Tournament', `Erro ao buscar usuário: ${err.message}`);
    res.status(500).json({ success: false, error: 'Erro ao buscar usuário' });
  }
});

// Vincular ID do jogo com o site
app.post('/tournament/link', (req, res) => {
  try {
    const { userId, deviceId, username } = req.body;
    
    if (!userId || !deviceId || !username) {
      return res.status(400).json({ error: 'Campos obrigatórios: userId, deviceId, username' });
    }

    TournamentManager.linkPlayer(userId, deviceId, username);
    res.json({ success: true, message: 'ID vinculado com sucesso!' });
  } catch (err) {
    Console.error('Tournament', `Erro ao vincular: ${err.message}`);
    res.status(500).json({ error: 'Erro ao vincular ID' });
  }
});

// Verificar se ID está vinculado (por userId)
app.get('/tournament/link/user/:userId', (req, res) => {
  try {
    const { userId } = req.params;
    const link = TournamentManager.getPlayerLinkByUserId(userId);
    
    if (!link) {
      return res.json({ linked: false });
    }

    res.json({ linked: true, ...link });
  } catch (err) {
    Console.error('Tournament', `Erro ao verificar link: ${err.message}`);
    res.status(500).json({ error: 'Erro ao verificar link' });
  }
});

// Verificar se ID está vinculado
app.get('/tournament/link/:deviceId', (req, res) => {
  try {
    const { deviceId } = req.params;
    const link = TournamentManager.getPlayerLink(deviceId);
    
    if (!link) {
      return res.json({ linked: false });
    }

    res.json({ linked: true, ...link });
  } catch (err) {
    Console.error('Tournament', `Erro ao verificar link: ${err.message}`);
    res.status(500).json({ error: 'Erro ao verificar link' });
  }
});

// Listar torneios ativos
app.get('/tournament/active', (req, res) => {
  try {
    const tournaments = TournamentManager.getActiveTournaments();
    res.json({ success: true, tournaments });
  } catch (err) {
    Console.error('Tournament', `Erro ao listar torneios: ${err.message}`);
    res.status(500).json({ error: 'Erro ao listar torneios' });
  }
});

// Listar todos os torneios
app.get('/tournament/all', (req, res) => {
  try {
    const tournaments = TournamentManager.getAllTournaments();
    res.json({ success: true, tournaments });
  } catch (err) {
    Console.error('Tournament', `Erro ao listar torneios: ${err.message}`);
    res.status(500).json({ error: 'Erro ao listar torneios' });
  }
});

// Obter detalhes de um torneio
app.get('/tournament/:id', (req, res) => {
  try {
    const { id } = req.params;
    const tournament = TournamentManager.getTournament(id);
    
    if (!tournament) {
      return res.status(404).json({ error: 'Torneio não encontrado' });
    }

    res.json({ success: true, tournament });
  } catch (err) {
    Console.error('Tournament', `Erro ao buscar torneio: ${err.message}`);
    res.status(500).json({ error: 'Erro ao buscar torneio' });
  }
});

// Inscrever jogador em torneio
app.post('/tournament/:id/register', (req, res) => {
  try {
    const { id } = req.params;
    const { userId } = req.body;
    
    if (!userId) {
      return res.status(400).json({ error: 'userId é obrigatório' });
    }

    const result = TournamentManager.registerPlayer(id, userId);
    
    if (result.error) {
      return res.status(400).json(result);
    }

    res.json(result);
  } catch (err) {
    Console.error('Tournament', `Erro ao registrar jogador: ${err.message}`);
    res.status(500).json({ error: 'Erro ao registrar jogador' });
  }
});

// Reportar vencedor de uma partida
app.post('/tournament/:tournamentId/match/:matchId/winner', (req, res) => {
  try {
    const { tournamentId, matchId } = req.params;
    const { winnerDeviceId } = req.body;
    
    if (!winnerDeviceId) {
      return res.status(400).json({ error: 'winnerDeviceId é obrigatório' });
    }

    const result = TournamentManager.reportWinner(tournamentId, matchId, winnerDeviceId);
    
    if (result.error) {
      return res.status(400).json(result);
    }

    res.json(result);
  } catch (err) {
    Console.error('Tournament', `Erro ao reportar vencedor: ${err.message}`);
    res.status(500).json({ error: 'Erro ao reportar vencedor' });
  }
});

// Obter partidas de um jogador
app.get('/tournament/player/:userId/matches', (req, res) => {
  try {
    const { userId } = req.params;
    const matches = TournamentManager.getPlayerMatches(userId);
    res.json({ success: true, matches });
  } catch (err) {
    Console.error('Tournament', `Erro ao buscar partidas: ${err.message}`);
    res.status(500).json({ error: 'Erro ao buscar partidas' });
  }
});

// ===== ROTAS DO BOT DISCORD (SEM AUTENTICAÇÃO) =====

// Status do bot
app.get('/bot/status', BotController.getStatus);

// Setar gemas
app.post('/bot/user/gems', BotController.setGems);

// Setar coroas
app.post('/bot/user/crowns', BotController.setCrowns);

// Setar troféus
app.post('/bot/user/trophies', BotController.setTrophies);

// Setar nickname
app.post('/bot/user/nickname', BotController.setNickname);

// Banir usuário
app.post('/bot/user/ban', BotController.banUser);

// Desbanir usuário
app.post('/bot/user/unban', BotController.unbanUser);

// Obter informações do usuário
app.get('/bot/user/:userId', BotController.getUserInfo);

// Adicionar sufixo [W] com cor hex
app.post('/bot/user/w', BotController.setWSuffix);

// Remover sufixo [W]
app.post('/bot/user/removew', BotController.removeWSuffix);

// Adicionar sufixo [B] (Booster)
app.post('/bot/user/b', BotController.setBSuffix);

// Remover sufixo [B]
app.post('/bot/user/removeb', BotController.removeBSuffix);

// ===== ROTAS COM AUTENTICAÇÃO =====
app.use(authenticate);

class CrownController {
  static async updateScore(req, res) {
    try {
      const { deviceid, username, country } = req.body;
      if (!deviceid || !username) {
        return res.status(400).json({ error: "Missing fields" });
      }

      let user = await UserModel.findByDeviceId(deviceid);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      const newCrowns = (user.crowns || 0) + 1;
      await UserModel.update(user.stumbleId, { crowns: newCrowns });

      res.json({ success: true, crowns: newCrowns });
    } catch (err) {
      console.error("Error updating crowns:", err);
      res.status(500).json({ error: "Internal server error" });
    }
  }

  static async list(req, res) {
    try {
      const { country, start, count } = req.query;

      const data = await UserModel.GetHighscore(
        "crowns",
        country || "",
        start || 0,
        count || 50
      );

      res.json(data);
    } catch (err) {
      console.error("Error fetching crown highscores:", err);
      res.status(500).json({ error: "Internal server error" });
    }
  }
}

app.post("/photon/auth", VerifyPhoton);
app.get("/onlinecheck", OnlineCheck);

app.get("/matchmaking/filter", MatchmakingController.getMatchmakingFilter);

app.post('/user/login', async (req, res) => {
  // Salvar a função send original
  const originalSend = res.send;
  const originalJson = res.json;
  
  // Sobrescrever res.json para interceptar a resposta
  res.json = function(data) {
    // Restaurar as funções originais
    res.send = originalSend;
    res.json = originalJson;
    
    // Se a resposta foi bem-sucedida e contém dados do usuário, registrar cliente
    if (res.statusCode === 200 && data && data.User) {
      try {
        const { DeviceId, StumbleId } = req.body;
        const user = data.User;
        
        // Registrar com múltiplos IDs para permitir kick por qualquer um deles
        const ids = [
          DeviceId,                    // DeviceId
          user.id?.toString(),         // ID numérico do MongoDB
          user.stumbleId,              // StumbleId
          StumbleId                    // StumbleId do request
        ].filter(id => id); // Remove valores undefined/null
        
        const clientInfo = {
          connectedAt: new Date(),
          deviceId: DeviceId,
          stumbleId: user.stumbleId,
          userId: user.id,
          username: user.username,
          autoRegistered: true
        };
        
        // Registrar com todos os IDs possíveis
        ids.forEach(id => {
          BotManager.registerClient(id, clientInfo);
        });
        
        Console.log('AutoRegister', `Cliente registrado com múltiplos IDs:`);
        Console.log('AutoRegister', `  - DeviceId: ${DeviceId}`);
        Console.log('AutoRegister', `  - User ID: ${user.id}`);
        Console.log('AutoRegister', `  - StumbleId: ${user.stumbleId}`);
        Console.log('AutoRegister', `  - Username: ${user.username}`);
        
        // Registrar automaticamente no TourX ".gg/sgzone"
        try {
          TourXManager.autoRegisterPlayer(user.id, user.username, user.stumbleId);
        } catch (err) {
          Console.log('AutoRegister', `Erro ao registrar no TourX: ${err.message}`);
        }
      } catch (err) {
        Console.log('AutoRegister', `Erro ao registrar automaticamente: ${err.message}`);
      }
    }
    
    // Enviar a resposta original
    return originalJson.call(this, data);
  };
  
  // Executar o login normal
  await UserController.login(req, res);
});
app.get('/user/config', (req, res) => {
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  sendShared(req, res);
});
app.get('/usersettings', UserController.getSettings);
app.post('/user/updateusername', validateUsernameMiddleware, UserController.updateUsername);

// Rota para atualização automática de username (sem validação extra)
app.post('/user/update-username', async (req, res) => {
  try {
    const { userId, newUsername } = req.body;
    
    if (!userId || !newUsername) {
      return res.status(400).json({ success: false, error: 'userId e newUsername são obrigatórios' });
    }
    
    // Atualizar no MongoDB
    const user = await UserModel.findByIdAndUpdate(
      userId,
      { username: newUsername },
      { new: true }
    );
    
    if (!user) {
      return res.status(404).json({ success: false, error: 'Usuário não encontrado' });
    }
    
    Console.log('Username', `Username atualizado: ${userId} -> ${newUsername}`);
    res.json({ success: true, username: newUsername });
  } catch (err) {
    Console.error('Username', `Erro ao atualizar: ${err.message}`);
    res.status(500).json({ success: false, error: 'Erro ao atualizar username' });
  }
});

app.get('/user/deleteaccount', UserController.deleteAccount);
app.post('/user/linkplatform', UserController.linkPlatform);
app.post('/user/unlinkplatform', UserController.unlinkPlatform);
app.get("/shared/:version/:type", (req, res) => {
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  sendShared(req, res);
});
app.post('/user/profile', UserController.getProfile);
app.post('/user-equipped-cosmetics/update', UserController.updateCosmetics);
app.post('/user/cosmetics/addskin', UserController.addSkin);
app.post('/user/cosmetics/setequipped', UserController.setEquippedCosmetic);

// Endpoints para gerenciamento de clientes conectados
app.post('/client/register', (req, res) => {
  try {
    const { userId, deviceId } = req.body;
    Console.log('Register', `Requisição recebida - userId: ${userId}, deviceId: ${deviceId}`);
    
    if (!userId && !deviceId) {
      Console.log('Register', 'Erro: userId ou deviceId não fornecido');
      return res.status(400).json({ error: 'userId or deviceId required' });
    }
    
    const clientId = userId || deviceId;
    BotManager.registerClient(clientId, { 
      connectedAt: new Date(),
      deviceId: deviceId,
      userId: userId
    });
    
    Console.log('Register', `Cliente ${clientId} registrado com sucesso`);
    res.json({ success: true, message: 'Client registered', clientId: clientId });
  } catch (err) {
    Console.error('Register', `Erro ao registrar: ${err.message}`);
    res.status(500).json({ error: 'Failed to register client' });
  }
});

app.post('/client/unregister', (req, res) => {
  try {
    const { userId, deviceId } = req.body;
    const clientId = userId || deviceId;
    
    BotManager.unregisterClient(clientId);
    res.json({ success: true, message: 'Client unregistered' });
  } catch (err) {
    Console.error('Unregister', `Erro: ${err.message}`);
    res.status(500).json({ error: 'Failed to unregister client' });
  }
});

app.get('/client/list', (req, res) => {
  try {
    const clients = BotManager.getConnectedClients();
    res.json({ 
      success: true, 
      count: clients.length,
      clients: clients 
    });
  } catch (err) {
    Console.error('ClientList', `Erro: ${err.message}`);
    res.status(500).json({ error: 'Failed to list clients' });
  }
});

app.get('/client/kick/check/:userId', (req, res) => {
  try {
    const userId = req.params.userId;
    const shouldKick = BotManager.isKicked(userId);
    
    res.json({
      success: true,
      userId: userId,
      shouldKick: shouldKick
    });
  } catch (err) {
    Console.error('KickCheck', `Erro: ${err.message}`);
    res.status(500).json({ error: 'Failed to check kick status' });
  }
});

app.get('/round/finish/:round', RoundController.finishRound);
app.get('/round/finishv2/:round', RoundController.finishRound);
app.post('/round/finish/v4/:round', RoundController.finishRoundV4);
app.post('/round/eventfinish/v4/:round', RoundController.finishRoundV4);

app.get('/battlepass', BattlePassController.getBattlePass);
app.post('/battlepass/claimv3', BattlePassController.claimReward);
app.post('/battlepass/purchase', BattlePassController.purchaseBattlePass);
app.post('/battlepass/complete', BattlePassController.completeBattlePass);

app.get('/economy/purchase/:item', EconomyController.purchase); 
app.get('/economy/purchasegasha/:itemId/:count', EconomyController.purchaseGasha); 
app.get('/economy/purchaseluckyspin', EconomyController.purchaseLuckySpin); 
app.get('/economy/purchasedrop/:itemId/:count', EconomyController.purchaseLuckySpin); 
app.post('/economy/:currencyType/give/:amount', EconomyController.giveCurrency); 

app.get('/missions', MissionsController.getMissions);
app.post('/missions/:missionId/rewards/claim/v2', MissionsController.claimMissionReward);
app.post('/missions/objective/:objectiveId/:milestoneId/rewards/claim/v2', MissionsController.claimMilestoneReward);

app.post('/friends/request/accept', FriendsController.add);
app.delete('/friends/:UserId', FriendsController.remove);
app.get('/friends', FriendsController.list);
app.post('/friends/search', FriendsController.search);
app.post('/friends/request', FriendsController.request);
app.post('/friends/accept', FriendsController.accept);
app.post('/friends/request/decline', FriendsController.reject);
app.post('/friends/cancel', FriendsController.cancel);
app.get('/friends/request', FriendsController.pending);

app.get("/game-events/me", EventsController.getActive);

app.get("/news/getall", NewsController.GetNews);

app.post('/analytics', AnalyticsController.analytic);

app.post("/update-crown-score", CrownController.updateScore);
app.get("/highscore/crowns/list", CrownController.list);

app.get('/highscore/:type/list/', async (req, res, next) => {
  try {
    const { type } = req.params;
    const { start = 0, count = 100, country = 'global' } = req.query;

    const startNum = parseInt(start, 10);
    const countNum = parseInt(count, 10);

    if (!type) {
      return res.status(400).json({ error: "O tipo é necessário" });
    }

    if (isNaN(startNum) || isNaN(countNum)) {
      return res.status(400).json({ error: "Os parâmetros start e count devem ser números" });
    }

    const result = await UserModel.GetHighscore(type, country, startNum, countNum);

    res.json(result);
  } catch (err) {
    next(err);
  }
});

app.get("/social/interactions", SocialController.getInteractions);

app.get("/tournamentx/active", (req, res) => {
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  TournamentXController.getActive(req, res);
});
app.get("/tournamentx/active/v2", (req, res) => {
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  TournamentXController.getActive(req, res);
});
app.post("/tournamentx/:tournamentId/join/v2", TournamentXController.join.bind(TournamentXController));
app.post("/tournamentx/:tournamentId/leave", TournamentXController.leave.bind(TournamentXController));
app.post("/tournamentx/:tournamentId/finish", TournamentXController.finish.bind(TournamentXController));

// ===== ROTAS DO TOURX .GG/SGZONE (1V1 BLOCK DASH) =====

app.get("/tourx/sgzone/info", (req, res) => {
  try {
    const tourXInfo = TourXManager.getActiveTourX();
    res.json({ success: true, tourX: tourXInfo });
  } catch (err) {
    Console.error('TourX', `Erro ao obter info: ${err.message}`);
    res.status(500).json({ success: false, error: 'Erro ao obter informações' });
  }
});

app.get("/tourx/sgzone/matches", (req, res) => {
  try {
    const matches = TourXManager.getActiveMatches();
    res.json({ success: true, matches });
  } catch (err) {
    Console.error('TourX', `Erro ao obter matches: ${err.message}`);
    res.status(500).json({ success: false, error: 'Erro ao obter matches' });
  }
});

app.post("/tourx/sgzone/match/:matchId/winner", (req, res) => {
  try {
    const { matchId } = req.params;
    const { userId } = req.body;

    if (!userId) {
      return res.status(400).json({ success: false, error: 'userId é obrigatório' });
    }

    const result = TourXManager.reportWinner(matchId, userId);
    
    if (!result.success) {
      return res.status(400).json(result);
    }

    res.json(result);
  } catch (err) {
    Console.error('TourX', `Erro ao reportar vencedor: ${err.message}`);
    res.status(500).json({ success: false, error: 'Erro ao reportar vencedor' });
  }
});

app.get("/tourx/sgzone/player/:userId/stats", (req, res) => {
  try {
    const { userId } = req.params;
    const stats = TourXManager.getPlayerStats(userId);

    if (!stats) {
      return res.status(404).json({ success: false, error: 'Jogador não encontrado' });
    }

    res.json({ success: true, stats });
  } catch (err) {
    Console.error('TourX', `Erro ao obter stats: ${err.message}`);
    res.status(500).json({ success: false, error: 'Erro ao obter estatísticas' });
  }
});

app.get("/tourx/sgzone/ranking", (req, res) => {
  try {
    const { limit = 10 } = req.query;
    const ranking = TourXManager.getRanking(parseInt(limit));
    res.json({ success: true, ranking });
  } catch (err) {
    Console.error('TourX', `Erro ao obter ranking: ${err.message}`);
    res.status(500).json({ success: false, error: 'Erro ao obter ranking' });
  }
});

app.get("/api/v1/ping", async (req, res) => {
  res.status(200).send("OK");
});
app.post("/api/v1/userLoginExternal", TournamentController.login);
app.get("/api/v1/tournaments", TournamentController.getActive);

// ===== ROTAS DE ADMINISTRAÇÃO - USER ID COUNTER =====

const UserIdCounter = require('./UserIdCounter');
app.get('/admin/userid/current', (req, res) => {
  try {
    const currentId = UserIdCounter.getCurrentId();
    res.json({
      success: true,
      currentId: currentId,
      message: `Próximo usuário receberá o ID ${currentId}`
    });
  } catch (err) {
    Console.error('Admin', `Erro ao obter ID atual: ${err.message}`);
    res.status(500).json({ error: 'Failed to get current ID' });
  }
});

// Definir próximo ID manualmente
app.post('/admin/userid/set', (req, res) => {
  try {
    const { nextId } = req.body;
    
    if (!nextId || isNaN(nextId)) {
      return res.status(400).json({ error: 'nextId (number) required' });
    }
    
    const success = UserIdCounter.setNextId(parseInt(nextId));
    
    if (!success) {
      return res.status(400).json({ error: 'ID must be >= 500' });
    }
    
    Console.log('Admin', `Próximo ID definido para ${nextId}`);
    
    res.json({
      success: true,
      message: `Next user ID set to ${nextId}`,
      nextId: parseInt(nextId)
    });
  } catch (err) {
    Console.error('Admin', `Erro ao definir ID: ${err.message}`);
    res.status(500).json({ error: 'Failed to set next ID' });
  }
});

// Resetar contador (apenas para testes!)
app.post('/admin/userid/reset', (req, res) => {
  try {
    UserIdCounter.reset();
    
    Console.warn('Admin', 'Contador de IDs resetado para 500!');
    
    res.json({
      success: true,
      message: 'User ID counter reset to 500',
      warning: 'This should only be used for testing!'
    });
  } catch (err) {
    Console.error('Admin', `Erro ao resetar contador: ${err.message}`);
    res.status(500).json({ error: 'Failed to reset counter' });
  }
});

// ===== ROTAS DE ADMINISTRAÇÃO - ANTI-CHEAT =====

// Estatísticas do anti-cheat
app.get('/admin/anticheat/stats', (req, res) => {
  try {
    const stats = AntiCheat.getStats();
    res.json({
      success: true,
      stats: stats,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    Console.error('Admin', `Erro ao obter stats: ${err.message}`);
    res.status(500).json({ error: 'Failed to get stats' });
  }
});

// Devices suspeitos
app.get('/admin/anticheat/suspicious/devices', (req, res) => {
  try {
    const devices = AntiCheat.getSuspiciousDevices();
    res.json({
      success: true,
      count: devices.length,
      devices: devices,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    Console.error('Admin', `Erro ao obter devices suspeitos: ${err.message}`);
    res.status(500).json({ error: 'Failed to get suspicious devices' });
  }
});

// IPs suspeitos
app.get('/admin/anticheat/suspicious/ips', (req, res) => {
  try {
    const ips = AntiCheat.getSuspiciousIPs();
    res.json({
      success: true,
      count: ips.length,
      ips: ips,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    Console.error('Admin', `Erro ao obter IPs suspeitos: ${err.message}`);
    res.status(500).json({ error: 'Failed to get suspicious IPs' });
  }
});

// Banir device
app.post('/admin/anticheat/ban', (req, res) => {
  try {
    const { deviceId, reason } = req.body;
    
    if (!deviceId) {
      return res.status(400).json({ error: 'deviceId required' });
    }
    
    AntiCheat.banDevice(deviceId, reason || 'Manual ban by admin');
    
    Console.log('Admin', `Device ${deviceId} banido: ${reason || 'Manual ban'}`);
    
    res.json({
      success: true,
      message: `Device ${deviceId} banned successfully`,
      deviceId: deviceId,
      reason: reason || 'Manual ban by admin'
    });
  } catch (err) {
    Console.error('Admin', `Erro ao banir: ${err.message}`);
    res.status(500).json({ error: 'Failed to ban device' });
  }
});

// Banir IP
app.post('/admin/anticheat/banip', (req, res) => {
  try {
    const { ip, reason } = req.body;
    
    if (!ip) {
      return res.status(400).json({ error: 'ip required' });
    }
    
    AntiCheat.banIP(ip, reason || 'Manual ban by admin');
    
    Console.log('Admin', `IP ${ip} banido: ${reason || 'Manual ban'}`);
    
    res.json({
      success: true,
      message: `IP ${ip} banned successfully`,
      ip: ip,
      reason: reason || 'Manual ban by admin'
    });
  } catch (err) {
    Console.error('Admin', `Erro ao banir IP: ${err.message}`);
    res.status(500).json({ error: 'Failed to ban IP' });
  }
});

// Desbanir device
app.post('/admin/anticheat/unban', (req, res) => {
  try {
    const { deviceId } = req.body;
    
    if (!deviceId) {
      return res.status(400).json({ error: 'deviceId required' });
    }
    
    AntiCheat.unbanDevice(deviceId);
    
    Console.log('Admin', `Device ${deviceId} desbanido`);
    
    res.json({
      success: true,
      message: `Device ${deviceId} unbanned successfully`,
      deviceId: deviceId
    });
  } catch (err) {
    Console.error('Admin', `Erro ao desbanir: ${err.message}`);
    res.status(500).json({ error: 'Failed to unban device' });
  }
});

// Desbanir IP
app.post('/admin/anticheat/unbanip', (req, res) => {
  try {
    const { ip } = req.body;
    
    if (!ip) {
      return res.status(400).json({ error: 'ip required' });
    }
    
    AntiCheat.unbanIP(ip);
    
    Console.log('Admin', `IP ${ip} desbanido`);
    
    res.json({
      success: true,
      message: `IP ${ip} unbanned successfully`,
      ip: ip
    });
  } catch (err) {
    Console.error('Admin', `Erro ao desbanir IP: ${err.message}`);
    res.status(500).json({ error: 'Failed to unban IP' });
  }
});

// Adicionar à whitelist
app.post('/admin/anticheat/whitelist', (req, res) => {
  try {
    const { deviceId } = req.body;
    
    if (!deviceId) {
      return res.status(400).json({ error: 'deviceId required' });
    }
    
    AntiCheat.whitelistDevice(deviceId);
    
    Console.log('Admin', `Device ${deviceId} adicionado à whitelist`);
    
    res.json({
      success: true,
      message: `Device ${deviceId} added to whitelist`,
      deviceId: deviceId
    });
  } catch (err) {
    Console.error('Admin', `Erro ao adicionar à whitelist: ${err.message}`);
    res.status(500).json({ error: 'Failed to whitelist device' });
  }
});

// Remover da whitelist
app.post('/admin/anticheat/unwhitelist', (req, res) => {
  try {
    const { deviceId } = req.body;
    
    if (!deviceId) {
      return res.status(400).json({ error: 'deviceId required' });
    }
    
    AntiCheat.removeFromWhitelist(deviceId);
    
    Console.log('Admin', `Device ${deviceId} removido da whitelist`);
    
    res.json({
      success: true,
      message: `Device ${deviceId} removed from whitelist`,
      deviceId: deviceId
    });
  } catch (err) {
    Console.error('Admin', `Erro ao remover da whitelist: ${err.message}`);
    res.status(500).json({ error: 'Failed to remove from whitelist' });
  }
});

// Resetar estatísticas (mantém bans)
app.post('/admin/anticheat/reset', (req, res) => {
  try {
    AntiCheat.resetStats();
    
    Console.log('Admin', 'Estatísticas do anti-cheat resetadas');
    
    res.json({
      success: true,
      message: 'Anti-cheat statistics reset successfully'
    });
  } catch (err) {
    Console.error('Admin', `Erro ao resetar stats: ${err.message}`);
    res.status(500).json({ error: 'Failed to reset stats' });
  }
});

// ===== ROTAS DE ADMINISTRAÇÃO - MIGRAÇÃO DE DADOS =====

// Migrar usernames de sgmasters para sgzone
app.post('/admin/migrate/usernames', async (req, res) => {
  try {
    const result = await UserModel.migrateUsernamesFromMastersToZone();
    
    Console.log('Admin', `Migração concluída: ${result.modifiedCount} usuários atualizados`);
    
    res.json({
      success: true,
      message: `Successfully migrated ${result.modifiedCount} usernames from sgmasters to sgzone`,
      modifiedCount: result.modifiedCount
    });
  } catch (err) {
    Console.error('Admin', `Erro ao migrar usernames: ${err.message}`);
    res.status(500).json({ error: 'Failed to migrate usernames', details: err.message });
  }
});

// ===== ROTAS DO BOT DISCORD =====

// Status do bot
app.get('/bot/status', BotController.getStatus);

// Setar gemas
app.post('/bot/user/gems', BotController.setGems);

// Setar coroas
app.post('/bot/user/crowns', BotController.setCrowns);

// Setar troféus
app.post('/bot/user/trophies', BotController.setTrophies);

// Setar nickname
app.post('/bot/user/nickname', BotController.setNickname);

// Banir usuário
app.post('/bot/user/ban', BotController.banUser);

// Desbanir usuário
app.post('/bot/user/unban', BotController.unbanUser);

// Obter informações do usuário
app.get('/bot/user/:userId', BotController.getUserInfo);

// Adicionar sufixo [W] com cor hex
app.post('/bot/user/w', BotController.setWSuffix);

// Remover sufixo [W]
app.post('/bot/user/removew', BotController.removeWSuffix);

// Adicionar sufixo [B] (Booster)
app.post('/bot/user/b', BotController.setBSuffix);

// Remover sufixo [B]
app.post('/bot/user/removeb', BotController.removeBSuffix);

app.use(errorControll);

app.listen(PORT, async () => {
  const currentDate = new Date().toLocaleString().replace(",", " |");
  console.clear();
  Console.log(
    "Server",
    `[${Title}] | ${currentDate} | ${CryptoUtils.SessionToken()}`
  );
  Console.log("Server", `Listening on port ${PORT}`);
  
  // Bot Discord é iniciado separadamente via discord-bot-slash.js
  Console.log("Server", "Bot Discord será iniciado separadamente");
});