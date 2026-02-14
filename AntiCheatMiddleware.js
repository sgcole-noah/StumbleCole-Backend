// AntiCheatMiddleware.js - Sistema avançado de proteção contra cheats e bypass
const Console = require("./ConsoleUtils");
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ===== CONFIGURAÇÕES =====
const ANTICHEAT_CONFIG = {
  BAN_AFTER_ATTEMPTS: 5,           // Ban automático após X tentativas (aumentado para evitar falsos positivos)
  TEMP_BLOCK_DURATION: 300000,     // 5 minutos de bloqueio temporário
  RATE_LIMIT_WINDOW: 60000,        // Janela de 1 minuto para rate limiting
  MAX_REQUESTS_PER_MINUTE: 50,     // Máximo de requisições por minuto (aumentado para jogabilidade normal)
  CLEANUP_INTERVAL: 3600000,       // Limpar dados antigos a cada 1 hora
  SAVE_BANS_INTERVAL: 60000,       // Salvar bans a cada 1 minuto
  INTEGRITY_CHECK_ENABLED: true,   // Verificar integridade de requisições
  DLL_HASH_CHECK_ENABLED: true,    // Verificar hash da DLL
  PERSISTENT_BANS: true,           // Salvar bans em arquivo
  GRACE_PERIOD: 3,                 // Número de avisos antes de contar para ban
  WHITELIST_SUBNET: true,          // Permitir múltiplos devices na mesma rede
  SMART_DETECTION: true,           // Usar detecção inteligente de padrões
  ADMIN_API_KEY: process.env.ADMIN_API_KEY || 'change-me-in-production' // Chave para endpoints admin
};

// Lista expandida de padrões suspeitos em usernames
const SUSPICIOUS_PATTERNS = [
  /<color=/i,           // Unity rich text color
  /<size=/i,            // Unity rich text size
  /<b>/i,               // Bold
  /<i>/i,               // Italic
  /<material=/i,        // Material
  /<quad/i,             // Quad
  /<sprite/i,           // Sprite
  /\\u[0-9a-f]{4}/i,    // Unicode escape
  /\\x[0-9a-f]{2}/i,    // Hex escape
  /[\u0000-\u001F]/,    // Control characters
  /[\u200B-\u200D]/,    // Zero-width characters
  /[\uFEFF]/,           // Zero-width no-break space
  /<\/?[a-z]+>/i,       // HTML/XML tags
  /\{[a-z]+\}/i,        // Template strings
  /\$\{/,               // Template literals
  /&#[0-9]+;/i,         // HTML entities
  /&[a-z]+;/i,          // Named HTML entities
  /%[0-9a-f]{2}/i,      // URL encoding
  /\x00/,               // Null bytes
  /[\uD800-\uDFFF]/,    // Surrogates (podem causar problemas)
];

// Padrões permitidos do servidor (whitelist)
const ALLOWED_SERVER_PATTERNS = [
  /^\.gg\/sgzone<#[0-9a-f]{6}><sup>\d+<\/sup>$/i  // Padrão oficial: .gg/sgzone<#ffff00><sup>500</sup>
];

// ===== ARMAZENAMENTO DE DADOS =====
const BANNED_DEVICES = new Set();
const BANNED_IPS = new Set();
const SUSPICIOUS_DEVICES = new Map(); // DeviceId -> { count, lastSeen, violations, warnings }
const BYPASS_ATTEMPTS = new Map(); // IP -> { count, lastAttempt, violations }
const RATE_LIMITS = new Map(); // IP -> { requests: [], lastReset }
const KNOWN_HASHES = new Map(); // DeviceId -> { dllHash, lastCheck, verified }
const WHITELIST_DEVICES = new Set(); // Devices VIP/Admin que não são verificados
const KNOWN_CHEAT_HASHES = new Set(); // Hashes conhecidos de cheats/xits
const TRUSTED_NETWORKS = new Map(); // IP subnet -> { deviceCount, trusted }
const DEVICE_FINGERPRINTS = new Map(); // DeviceId -> { userAgent, screenRes, timezone }

// Arquivo para persistir bans
const BANS_FILE = path.join(__dirname, 'anticheat_bans.json');

// ===== FUNÇÕES DE PERSISTÊNCIA =====

/**
 * Carrega bans salvos do arquivo
 */
function loadBans() {
  try {
    if (fs.existsSync(BANS_FILE)) {
      const data = JSON.parse(fs.readFileSync(BANS_FILE, 'utf8'));
      
      if (data.devices) {
        data.devices.forEach(d => BANNED_DEVICES.add(d));
      }
      if (data.ips) {
        data.ips.forEach(ip => BANNED_IPS.add(ip));
      }
      if (data.whitelist) {
        data.whitelist.forEach(d => WHITELIST_DEVICES.add(d));
      }
      if (data.knownCheatHashes) {
        data.knownCheatHashes.forEach(h => KNOWN_CHEAT_HASHES.add(h));
      }
      
      Console.log('[ANTI-CHEAT]', `Carregados ${BANNED_DEVICES.size} devices banidos, ${BANNED_IPS.size} IPs banidos e ${KNOWN_CHEAT_HASHES.size} hashes de cheats`);
    }
  } catch (err) {
    Console.error('[ANTI-CHEAT]', `Erro ao carregar bans: ${err.message}`);
  }
}

/**
 * Salva bans no arquivo
 */
function saveBans() {
  try {
    const data = {
      devices: Array.from(BANNED_DEVICES),
      ips: Array.from(BANNED_IPS),
      whitelist: Array.from(WHITELIST_DEVICES),
      knownCheatHashes: Array.from(KNOWN_CHEAT_HASHES),
      lastUpdate: new Date().toISOString()
    };
    
    fs.writeFileSync(BANS_FILE, JSON.stringify(data, null, 2));
  } catch (err) {
    Console.error('[ANTI-CHEAT]', `Erro ao salvar bans: ${err.message}`);
  }
}

// ===== FUNÇÕES DE SANITIZAÇÃO =====

/**
 * Extrai subnet do IP (primeiros 3 octetos)
 */
function getSubnet(ip) {
  if (!ip) return null;
  const parts = ip.split('.');
  if (parts.length >= 3) {
    return `${parts[0]}.${parts[1]}.${parts[2]}`;
  }
  return null;
}

/**
 * Verifica se um IP pertence a uma rede confiável
 */
function isTrustedNetwork(ip) {
  if (!ANTICHEAT_CONFIG.WHITELIST_SUBNET) return false;
  
  const subnet = getSubnet(ip);
  if (!subnet) return false;
  
  const networkData = TRUSTED_NETWORKS.get(subnet);
  return networkData && networkData.trusted;
}

/**
 * Registra device em uma rede
 */
function registerDeviceInNetwork(ip, deviceId) {
  const subnet = getSubnet(ip);
  if (!subnet) return;
  
  if (!TRUSTED_NETWORKS.has(subnet)) {
    TRUSTED_NETWORKS.set(subnet, { deviceCount: 0, devices: new Set(), trusted: false });
  }
  
  const networkData = TRUSTED_NETWORKS.get(subnet);
  networkData.devices.add(deviceId);
  networkData.deviceCount = networkData.devices.size;
  
  // Marca como confiável se tem múltiplos devices sem violações
  if (networkData.deviceCount >= 3) {
    const hasViolations = Array.from(networkData.devices).some(d => SUSPICIOUS_DEVICES.has(d));
    if (!hasViolations) {
      networkData.trusted = true;
    }
  }
}

/**
 * Cria fingerprint do device baseado em múltiplos fatores
 */
function createDeviceFingerprint(req) {
  const userAgent = req.headers['user-agent'] || '';
  const acceptLanguage = req.headers['accept-language'] || '';
  const acceptEncoding = req.headers['accept-encoding'] || '';
  
  return {
    userAgent,
    acceptLanguage,
    acceptEncoding,
    timestamp: Date.now()
  };
}

/**
 * Verifica se o fingerprint do device mudou (possível device spoofing)
 */
function verifyDeviceFingerprint(deviceId, req) {
  const newFingerprint = createDeviceFingerprint(req);
  
  if (!DEVICE_FINGERPRINTS.has(deviceId)) {
    DEVICE_FINGERPRINTS.set(deviceId, newFingerprint);
    return true;
  }
  
  const oldFingerprint = DEVICE_FINGERPRINTS.get(deviceId);
  
  // Verifica se mudou drasticamente (possível spoofing)
  if (oldFingerprint.userAgent !== newFingerprint.userAgent) {
    Console.warn(`[ANTI-CHEAT] Device fingerprint mudou: ${deviceId}`);
    return false;
  }
  
  // Atualiza timestamp
  DEVICE_FINGERPRINTS.set(deviceId, newFingerprint);
  return true;
}

/**
 * Adiciona hash de cheat conhecido à blacklist
 */
function addKnownCheatHash(hash, description = '') {
  KNOWN_CHEAT_HASHES.add(hash);
  Console.warn(`[ANTI-CHEAT] Hash de cheat adicionado: ${hash.substring(0, 16)}... (${description})`);
  saveBans();
}

/**
 * Verifica se um hash é de um cheat conhecido
 */
function isKnownCheatHash(hash) {
  return KNOWN_CHEAT_HASHES.has(hash);
}

// ===== FUNÇÕES DE SANITIZAÇÃO =====

/**
 * Verifica se o username é um padrão oficial do servidor
 */
function isServerUsername(username) {
  if (!username || typeof username !== 'string') {
    return false;
  }
  
  for (const pattern of ALLOWED_SERVER_PATTERNS) {
    if (pattern.test(username)) {
      return true;
    }
  }
  
  return false;
}

/**
 * Sanitiza completamente um username removendo qualquer formatação
 */
function sanitizeUsername(username) {
  if (!username || typeof username !== 'string') {
    return '';
  }

  // Se é um username oficial do servidor, não sanitiza
  if (isServerUsername(username)) {
    Console.info('[ANTI-CHEAT]', `Username do servidor detectado, mantendo formatação: ${username}`);
    return username;
  }

  // Remove todos os caracteres especiais e formatação
  let sanitized = username
    .replace(/<[^>]*>/g, '')           // Remove tags HTML/Unity
    .replace(/\\u[0-9a-f]{4}/gi, '')   // Remove unicode escapes
    .replace(/\\x[0-9a-f]{2}/gi, '')   // Remove hex escapes
    .replace(/&#[0-9]+;/gi, '')        // Remove HTML entities
    .replace(/&[a-z]+;/gi, '')         // Remove named entities
    .replace(/%[0-9a-f]{2}/gi, '')     // Remove URL encoding
    .replace(/[\u0000-\u001F]/g, '')   // Remove control chars
    .replace(/[\u200B-\u200D\uFEFF]/g, '') // Remove zero-width chars
    .replace(/[\uD800-\uDFFF]/g, '')   // Remove surrogates
    .replace(/[^\w\s-]/g, '')          // Mantém apenas alfanuméricos, espaços e hífens
    .trim()
    .substring(0, 20);                 // Limita tamanho

  return sanitized;
}

/**
 * Verifica se um username contém padrões suspeitos
 */
function containsSuspiciousPatterns(username) {
  if (!username) return false;
  
  // Se é um username oficial do servidor, permite
  if (isServerUsername(username)) {
    return false;
  }
  
  for (const pattern of SUSPICIOUS_PATTERNS) {
    if (pattern.test(username)) {
      return true;
    }
  }
  
  return false;
}

/**
 * Valida se um username é legítimo
 */
function isValidUsername(username) {
  if (!username || typeof username !== 'string') {
    return false;
  }

  // Se é um username oficial do servidor, sempre válido
  if (isServerUsername(username)) {
    return true;
  }

  // Verifica tamanho
  if (username.length < 3 || username.length > 20) {
    return false;
  }

  // Verifica padrões suspeitos
  if (containsSuspiciousPatterns(username)) {
    return false;
  }

  // Apenas letras, números, underscores e hífens
  if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
    return false;
  }

  return true;
}

// ===== RATE LIMITING =====

/**
 * Verifica rate limiting por IP
 */
function checkRateLimit(ip) {
  const now = Date.now();
  
  if (!RATE_LIMITS.has(ip)) {
    RATE_LIMITS.set(ip, { requests: [now], lastReset: now });
    return true;
  }
  
  const data = RATE_LIMITS.get(ip);
  
  // Remove requisições antigas (fora da janela)
  data.requests = data.requests.filter(time => now - time < ANTICHEAT_CONFIG.RATE_LIMIT_WINDOW);
  
  // Adiciona nova requisição
  data.requests.push(now);
  
  // Verifica se excedeu o limite
  if (data.requests.length > ANTICHEAT_CONFIG.MAX_REQUESTS_PER_MINUTE) {
    return false;
  }
  
  return true;
}

// ===== DETECÇÃO DE BYPASS =====

/**
 * Registra tentativa de bypass
 */
function logBypassAttempt(ip, deviceId, username, reason, severity = 'medium') {
  const now = Date.now();
  
  // Verifica se é rede confiável - reduz severidade
  if (isTrustedNetwork(ip) && severity !== 'critical') {
    Console.info(`[ANTI-CHEAT] Tentativa em rede confiável - severidade reduzida`);
    if (severity === 'high') severity = 'medium';
    if (severity === 'medium') severity = 'low';
  }
  
  if (!BYPASS_ATTEMPTS.has(ip)) {
    BYPASS_ATTEMPTS.set(ip, { count: 0, lastAttempt: now, violations: [] });
  }
  
  const attempts = BYPASS_ATTEMPTS.get(ip);
  attempts.count++;
  attempts.lastAttempt = now;
  attempts.violations.push({
    timestamp: now,
    reason,
    severity,
    deviceId,
    username
  });
  
  Console.warn(`[ANTI-CHEAT] Tentativa de bypass detectada!`);
  Console.warn(`  IP: ${ip}`);
  Console.warn(`  DeviceId: ${deviceId}`);
  Console.warn(`  Username: ${username}`);
  Console.warn(`  Razão: ${reason}`);
  Console.warn(`  Severidade: ${severity}`);
  Console.warn(`  Tentativas totais: ${attempts.count}`);
  
  // Marca device como suspeito
  if (!SUSPICIOUS_DEVICES.has(deviceId)) {
    SUSPICIOUS_DEVICES.set(deviceId, { count: 0, lastSeen: now, violations: [], warnings: 0 });
  }
  const deviceData = SUSPICIOUS_DEVICES.get(deviceId);
  deviceData.lastSeen = now;
  deviceData.violations.push({ timestamp: now, reason, severity });
  
  // Sistema de avisos - só conta para ban após período de graça
  if (severity === 'low') {
    deviceData.warnings++;
    Console.info(`[ANTI-CHEAT] Aviso ${deviceData.warnings}/${ANTICHEAT_CONFIG.GRACE_PERIOD} para device ${deviceId}`);
    
    if (deviceData.warnings >= ANTICHEAT_CONFIG.GRACE_PERIOD) {
      deviceData.count++;
      deviceData.warnings = 0; // Reset avisos
    }
  } else {
    deviceData.count++;
  }
  
  // Ban automático baseado em severidade
  const banThreshold = ANTICHEAT_CONFIG.BAN_AFTER_ATTEMPTS;
  
  if (severity === 'critical') {
    BANNED_DEVICES.add(deviceId);
    BANNED_IPS.add(ip);
    Console.error(`[ANTI-CHEAT] Device ${deviceId} e IP ${ip} BANIDOS automaticamente (CRITICAL)!`);
    saveBans();
  } else if (deviceData.count >= banThreshold || attempts.count >= banThreshold * 2) {
    BANNED_DEVICES.add(deviceId);
    BANNED_IPS.add(ip);
    Console.error(`[ANTI-CHEAT] Device ${deviceId} e IP ${ip} BANIDOS automaticamente (threshold atingido)!`);
    saveBans();
  }
}

/**
 * Middleware principal de anti-cheat
 */
function antiCheatCheck(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress;
  const deviceId = req.body?.DeviceId || req.headers['x-device-id'];
  
  // Registra device na rede
  if (deviceId && ip) {
    registerDeviceInNetwork(ip, deviceId);
  }
  
  // Verifica whitelist (VIPs/Admins)
  if (deviceId && WHITELIST_DEVICES.has(deviceId)) {
    return next();
  }
  
  // Verifica fingerprint do device (anti-spoofing)
  if (deviceId && ANTICHEAT_CONFIG.SMART_DETECTION) {
    if (!verifyDeviceFingerprint(deviceId, req)) {
      Console.warn(`[ANTI-CHEAT] Device fingerprint suspeito: ${deviceId}`);
      logBypassAttempt(ip, deviceId, 'N/A', 'Device fingerprint mudou (possível spoofing)', 'medium');
    }
  }
  
  // Verifica se o IP está banido
  if (BANNED_IPS.has(ip)) {
    Console.error(`[ANTI-CHEAT] IP banido tentou acessar: ${ip}`);
    return res.status(403).json({
      ResultCode: -1,
      Message: "Your IP has been banned for cheating"
    });
  }
  
  // Verifica se o device está banido
  if (deviceId && BANNED_DEVICES.has(deviceId)) {
    Console.error(`[ANTI-CHEAT] Device banido tentou acessar: ${deviceId}`);
    return res.status(403).json({
      ResultCode: -1,
      Message: "Device banned for cheating"
    });
  }
  
  // Verifica rate limiting (mais leniente para redes confiáveis)
  const isRateLimited = !checkRateLimit(ip);
  if (isRateLimited && !isTrustedNetwork(ip)) {
    Console.warn(`[ANTI-CHEAT] Rate limit excedido: ${ip}`);
    logBypassAttempt(ip, deviceId, 'N/A', 'Rate limit exceeded', 'low');
    return res.status(429).json({
      ResultCode: -1,
      Message: "Too many requests. Please slow down."
    });
  }
  
  // Verifica bloqueio temporário por tentativas de bypass
  if (BYPASS_ATTEMPTS.has(ip)) {
    const attempts = BYPASS_ATTEMPTS.get(ip);
    const timeSinceLastAttempt = Date.now() - attempts.lastAttempt;
    
    // Se teve muitas tentativas recentes, bloqueia temporariamente
    if (attempts.count >= 8 && timeSinceLastAttempt < ANTICHEAT_CONFIG.TEMP_BLOCK_DURATION) {
      Console.warn(`[ANTI-CHEAT] IP bloqueado temporariamente: ${ip}`);
      return res.status(429).json({
        ResultCode: -1,
        Message: "Too many suspicious requests. Try again later."
      });
    }
  }
  
  next();
}

/**
 * Middleware específico para validação de username
 */
function validateUsernameMiddleware(req, res, next) {
  const username = req.body?.Username || req.body?.username;
  
  if (!username) {
    return next(); // Se não tem username, deixa passar
  }
  
  const ip = req.ip || req.connection.remoteAddress;
  const deviceId = req.body?.DeviceId || req.headers['x-device-id'];
  
  // Verifica whitelist
  if (deviceId && WHITELIST_DEVICES.has(deviceId)) {
    return next();
  }
  
  // Verifica padrões suspeitos
  if (containsSuspiciousPatterns(username)) {
    // Apenas aviso, não ban imediato
    logBypassAttempt(ip, deviceId, username, "Padrões de formatação detectados", 'low');
    
    // Sanitiza o username automaticamente
    const sanitized = sanitizeUsername(username);
    req.body.Username = sanitized;
    req.body.username = sanitized;
    
    Console.warn(`[ANTI-CHEAT] Username sanitizado: "${username}" -> "${sanitized}"`);
    
    // Se ficou vazio após sanitização, gera um padrão
    if (!sanitized || sanitized.length < 3) {
      req.body.Username = `Player${Math.floor(Math.random() * 10000)}`;
      req.body.username = req.body.Username;
    }
  }
  
  // Valida o username final
  const finalUsername = req.body.Username || req.body.username;
  if (!isValidUsername(finalUsername)) {
    // Segunda tentativa de sanitização
    const reSanitized = sanitizeUsername(finalUsername);
    
    if (isValidUsername(reSanitized)) {
      req.body.Username = reSanitized;
      req.body.username = reSanitized;
      Console.info(`[ANTI-CHEAT] Username re-sanitizado com sucesso: "${reSanitized}"`);
    } else {
      // Só agora registra como violação mais séria
      logBypassAttempt(ip, deviceId, finalUsername, "Username inválido após múltiplas sanitizações", 'medium');
      
      return res.status(422).json({
        ResultCode: -1,
        Message: "Invalid username format. Only letters, numbers, underscores and hyphens allowed (3-20 characters)."
      });
    }
  }
  
  next();
}

/**
 * Verifica integridade de requisições críticas
 */
function checkRequestIntegrity(req, res, next) {
  if (!ANTICHEAT_CONFIG.INTEGRITY_CHECK_ENABLED) {
    return next();
  }
  
  const body = req.body;
  const headers = req.headers;
  const ip = req.ip || req.connection.remoteAddress;
  const deviceId = body?.DeviceId;
  
  // Verifica whitelist
  if (deviceId && WHITELIST_DEVICES.has(deviceId)) {
    return next();
  }
  
  // Verifica se há tentativa de injeção de código
  const bodyStr = JSON.stringify(body);
  
  if (/<script|javascript:|onerror=|onload=|eval\(|Function\(/i.test(bodyStr)) {
    logBypassAttempt(ip, deviceId, 'N/A', "Tentativa de injeção de código", 'critical');
    
    return res.status(400).json({
      ResultCode: -1,
      Message: "Invalid request"
    });
  }
  
  // Verifica tamanho suspeito de requisição (possível flood)
  if (bodyStr.length > 100000) { // 100KB
    logBypassAttempt(ip, deviceId, 'N/A', "Requisição muito grande (possível flood)", 'high');
    
    return res.status(413).json({
      ResultCode: -1,
      Message: "Request too large"
    });
  }
  
  // Verifica headers suspeitos
  const suspiciousHeaders = ['x-forwarded-for', 'x-real-ip', 'x-original-ip'];
  for (const header of suspiciousHeaders) {
    if (headers[header] && headers[header].split(',').length > 3) {
      logBypassAttempt(ip, deviceId, 'N/A', "Headers suspeitos (possível proxy chain)", 'medium');
      break;
    }
  }
  
  next();
}

/**
 * Middleware para autenticar endpoints administrativos
 */
function authenticateAdmin(req, res, next) {
  const apiKey = req.headers['x-api-key'] || req.query.apiKey;
  
  if (!apiKey || apiKey !== ANTICHEAT_CONFIG.ADMIN_API_KEY) {
    Console.warn(`[ANTI-CHEAT] Tentativa de acesso admin não autorizada: ${req.ip}`);
    return res.status(401).json({
      success: false,
      error: 'Unauthorized - Invalid API key'
    });
  }
  
  next();
}

/**
 * Verifica hash da DLL reportado pelo cliente
 */
function verifyDLLHash(dllHash, deviceId) {
  // Verifica se é um hash de cheat conhecido
  if (isKnownCheatHash(dllHash)) {
    Console.error(`[ANTI-CHEAT] Hash de cheat conhecido detectado! Device: ${deviceId}, Hash: ${dllHash.substring(0, 16)}...`);
    return {
      valid: false,
      reason: 'known_cheat',
      action: 'ban'
    };
  }
  
  // Verifica se o hash é o legítimo (se configurado)
  const legitimateHash = process.env.LEGITIMATE_DLL_HASH;
  
  if (legitimateHash && legitimateHash !== 'LEGITIMATE_HASH_PLACEHOLDER') {
    if (dllHash !== legitimateHash) {
      Console.warn(`[ANTI-CHEAT] Hash de DLL não corresponde ao legítimo! Device: ${deviceId}`);
      Console.warn(`[ANTI-CHEAT] Esperado: ${legitimateHash.substring(0, 16)}...`);
      Console.warn(`[ANTI-CHEAT] Recebido: ${dllHash.substring(0, 16)}...`);
      
      return {
        valid: false,
        reason: 'hash_mismatch',
        action: 'warn'
      };
    }
  }
  
  // Atualiza registro de hash conhecido
  if (!KNOWN_HASHES.has(deviceId)) {
    KNOWN_HASHES.set(deviceId, { dllHash, lastCheck: Date.now(), verified: true });
  } else {
    const knownData = KNOWN_HASHES.get(deviceId);
    
    // Verifica se o hash mudou (possível troca de DLL)
    if (knownData.dllHash !== dllHash) {
      Console.warn(`[ANTI-CHEAT] Hash de DLL mudou para device ${deviceId}!`);
      Console.warn(`[ANTI-CHEAT] Anterior: ${knownData.dllHash.substring(0, 16)}...`);
      Console.warn(`[ANTI-CHEAT] Novo: ${dllHash.substring(0, 16)}...`);
      
      return {
        valid: false,
        reason: 'hash_changed',
        action: 'warn'
      };
    }
    
    knownData.lastCheck = Date.now();
  }
  
  return {
    valid: true,
    reason: 'verified',
    action: 'allow'
  };
}

/**
 * Middleware para verificar assinatura de requisições (futuro)
 */
function verifyRequestSignature(req, res, next) {
  // TODO: Implementar verificação de assinatura criptográfica
  // Isso pode incluir verificar um hash da DLL do cliente
  next();
}

/**
 * Adiciona device à lista de banidos
 */
function banDevice(deviceId, reason = "Cheating detected") {
  BANNED_DEVICES.add(deviceId);
  Console.error(`[ANTI-CHEAT] Device ${deviceId} banido: ${reason}`);
  saveBans();
}

/**
 * Adiciona IP à lista de banidos
 */
function banIP(ip, reason = "Cheating detected") {
  BANNED_IPS.add(ip);
  Console.error(`[ANTI-CHEAT] IP ${ip} banido: ${reason}`);
  saveBans();
}

/**
 * Remove device da lista de banidos
 */
function unbanDevice(deviceId) {
  BANNED_DEVICES.delete(deviceId);
  SUSPICIOUS_DEVICES.delete(deviceId);
  Console.info(`[ANTI-CHEAT] Device ${deviceId} desbanido`);
  saveBans();
}

/**
 * Remove IP da lista de banidos
 */
function unbanIP(ip) {
  BANNED_IPS.delete(ip);
  BYPASS_ATTEMPTS.delete(ip);
  Console.info(`[ANTI-CHEAT] IP ${ip} desbanido`);
  saveBans();
}

/**
 * Adiciona device à whitelist (VIP/Admin)
 */
function whitelistDevice(deviceId) {
  WHITELIST_DEVICES.add(deviceId);
  // Remove de listas de ban se estiver
  BANNED_DEVICES.delete(deviceId);
  SUSPICIOUS_DEVICES.delete(deviceId);
  Console.info(`[ANTI-CHEAT] Device ${deviceId} adicionado à whitelist`);
  saveBans();
}

/**
 * Remove device da whitelist
 */
function removeFromWhitelist(deviceId) {
  WHITELIST_DEVICES.delete(deviceId);
  Console.info(`[ANTI-CHEAT] Device ${deviceId} removido da whitelist`);
  saveBans();
}

/**
 * Retorna estatísticas do anti-cheat
 */
function getStats() {
  const totalViolations = Array.from(BYPASS_ATTEMPTS.values())
    .reduce((sum, v) => sum + v.count, 0);
  
  const recentViolations = Array.from(BYPASS_ATTEMPTS.values())
    .filter(v => Date.now() - v.lastAttempt < 3600000) // Última hora
    .reduce((sum, v) => sum + v.count, 0);
  
  return {
    bannedDevices: BANNED_DEVICES.size,
    bannedIPs: BANNED_IPS.size,
    suspiciousDevices: SUSPICIOUS_DEVICES.size,
    whitelistedDevices: WHITELIST_DEVICES.size,
    knownCheatHashes: KNOWN_CHEAT_HASHES.size,
    trustedNetworks: TRUSTED_NETWORKS.size,
    verifiedDLLs: KNOWN_HASHES.size,
    totalViolations,
    recentViolations,
    activeRateLimits: RATE_LIMITS.size,
    config: ANTICHEAT_CONFIG
  };
}

/**
 * Retorna lista detalhada de devices suspeitos
 */
function getSuspiciousDevices() {
  const devices = [];
  
  for (const [deviceId, data] of SUSPICIOUS_DEVICES.entries()) {
    devices.push({
      deviceId,
      violationCount: data.count,
      lastSeen: new Date(data.lastSeen).toISOString(),
      violations: data.violations || []
    });
  }
  
  // Ordena por número de violações (maior primeiro)
  devices.sort((a, b) => b.violationCount - a.violationCount);
  
  return devices;
}

/**
 * Retorna lista detalhada de IPs suspeitos
 */
function getSuspiciousIPs() {
  const ips = [];
  
  for (const [ip, data] of BYPASS_ATTEMPTS.entries()) {
    ips.push({
      ip,
      attemptCount: data.count,
      lastAttempt: new Date(data.lastAttempt).toISOString(),
      violations: data.violations || []
    });
  }
  
  // Ordena por número de tentativas (maior primeiro)
  ips.sort((a, b) => b.attemptCount - a.attemptCount);
  
  return ips;
}

/**
 * Limpa dados antigos (executar periodicamente)
 */
function cleanup() {
  const now = Date.now();
  const ONE_HOUR = 3600000;
  const ONE_DAY = 86400000;
  
  let cleaned = 0;
  
  // Limpa tentativas antigas de bypass (1 hora)
  for (const [ip, data] of BYPASS_ATTEMPTS.entries()) {
    if (now - data.lastAttempt > ONE_HOUR) {
      BYPASS_ATTEMPTS.delete(ip);
      cleaned++;
    }
  }
  
  // Limpa devices suspeitos antigos (24 horas, mas mantém banidos)
  for (const [deviceId, data] of SUSPICIOUS_DEVICES.entries()) {
    if (!BANNED_DEVICES.has(deviceId) && now - data.lastSeen > ONE_DAY) {
      SUSPICIOUS_DEVICES.delete(deviceId);
      cleaned++;
    }
  }
  
  // Limpa rate limits antigos
  for (const [ip, data] of RATE_LIMITS.entries()) {
    if (now - data.lastReset > ONE_HOUR) {
      RATE_LIMITS.delete(ip);
      cleaned++;
    }
  }
  
  Console.info(`[ANTI-CHEAT] Cleanup executado - ${cleaned} entradas removidas`);
}

/**
 * Reseta estatísticas (mantém bans)
 */
function resetStats() {
  BYPASS_ATTEMPTS.clear();
  SUSPICIOUS_DEVICES.clear();
  RATE_LIMITS.clear();
  Console.info(`[ANTI-CHEAT] Estatísticas resetadas`);
}

// ===== INICIALIZAÇÃO =====

// Carrega bans salvos
if (ANTICHEAT_CONFIG.PERSISTENT_BANS) {
  loadBans();
}

// Executa cleanup periodicamente
setInterval(cleanup, ANTICHEAT_CONFIG.CLEANUP_INTERVAL);

// Salva bans periodicamente
if (ANTICHEAT_CONFIG.PERSISTENT_BANS) {
  setInterval(saveBans, ANTICHEAT_CONFIG.SAVE_BANS_INTERVAL);
}

Console.log('[ANTI-CHEAT]', 'Sistema anti-cheat avançado inicializado');
Console.log('[ANTI-CHEAT]', `Configuração: Ban após ${ANTICHEAT_CONFIG.BAN_AFTER_ATTEMPTS} tentativas`);
Console.log('[ANTI-CHEAT]', `Rate limit: ${ANTICHEAT_CONFIG.MAX_REQUESTS_PER_MINUTE} req/min`);

module.exports = {
  // Middlewares
  antiCheatCheck,
  validateUsernameMiddleware,
  checkRequestIntegrity,
  verifyRequestSignature,
  authenticateAdmin,
  
  // Funções de sanitização
  sanitizeUsername,
  isValidUsername,
  containsSuspiciousPatterns,
  
  // Funções administrativas
  banDevice,
  banIP,
  unbanDevice,
  unbanIP,
  whitelistDevice,
  removeFromWhitelist,
  
  // Funções de DLL/Cheat
  addKnownCheatHash,
  isKnownCheatHash,
  verifyDLLHash,
  
  // Funções de consulta
  getStats,
  getSuspiciousDevices,
  getSuspiciousIPs,
  
  // Funções de manutenção
  cleanup,
  resetStats,
  saveBans,
  loadBans
};
