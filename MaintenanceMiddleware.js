const BotManager = require('./BotManager');

function checkMaintenance(req, res, next) {
  // Verificar se está em modo de manutenção
  if (BotManager.isMaintenanceMode()) {
    // Permitir apenas endpoints essenciais
    const allowedPaths = ['/api/v1/ping', '/onlinecheck'];
    
    if (!allowedPaths.includes(req.path)) {
      return res.status(503).json({
        error: 'maintenance',
        message: 'O servidor está em manutenção. Tente novamente mais tarde.',
        maintenance: true
      });
    }
  }
  
  // Verificar se o jogador foi expulso (ban temporário)
  if (req.user) {
    const userId = req.user.id?.toString();
    const deviceId = req.user.deviceId;
    const stumbleId = req.user.stumbleId;
    
    if (BotManager.checkKicked(userId, deviceId, stumbleId)) {
      return res.status(403).json({
        error: 'kicked',
        message: 'Você foi expulso do servidor por um administrador.',
        kicked: true
      });
    }
  }
  
  next();
}

module.exports = { checkMaintenance };
