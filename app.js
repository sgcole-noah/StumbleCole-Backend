const API_URL = '';

let currentUserId = null;
let currentUserData = null;

// Carregar dados ao iniciar
document.addEventListener('DOMContentLoaded', () => {
    // Carregar userId salvo
    currentUserId = localStorage.getItem('userId');
    if (currentUserId) {
        document.getElementById('userId').value = currentUserId;
        checkLinkStatus();
    }

    // Event listeners
    document.getElementById('link-form').addEventListener('submit', handleLinkSubmit);

    // Carregar torneios
    loadTournaments();

    // Atualizar a cada 5 segundos
    setInterval(() => {
        loadTournaments();
        if (currentUserId) {
            loadMatches();
        }
    }, 5000);
});

async function handleLinkSubmit(e) {
    e.preventDefault();
    
    const userIdInput = document.getElementById('userId');
    
    if (!userIdInput) {
        console.error('Elemento userId não encontrado!');
        showStatus('error', '❌ Erro: Elemento não encontrado');
        return;
    }
    
    const userId = userIdInput.value.trim();
    
    if (!userId) {
        showStatus('error', '❌ Por favor, digite seu ID');
        return;
    }

    try {
        const response = await fetch(`${API_URL}/tournament/user/${userId}`);
        const data = await response.json();

        if (data.success && data.user) {
            currentUserData = data.user;
            showConfirmModal(data.user);
        } else {
            showStatus('error', '❌ ' + (data.error || 'Usuário não encontrado'));
        }
    } catch (err) {
        showStatus('error', '❌ Erro de conexão com o servidor');
        console.error(err);
    }
}

function showConfirmModal(user) {
    const modal = document.getElementById('confirm-modal');
    const userInfo = document.getElementById('user-info');
    
    userInfo.innerHTML = `
        <div class="user-info-item">
            <span class="user-info-label">ID:</span>
            <span class="user-info-value">${user.id}</span>
        </div>
        <div class="user-info-item">
            <span class="user-info-label">Nome de Usuário:</span>
            <span class="user-info-value">${user.username}</span>
        </div>
        <div class="user-info-item">
            <span class="user-info-label">Device ID:</span>
            <span class="user-info-value">${user.deviceId}</span>
        </div>
    `;
    
    document.body.classList.add('modal-open');
    modal.style.display = 'flex';
    modal.classList.add('show');
}

function closeModal() {
    const modal = document.getElementById('confirm-modal');
    document.body.classList.remove('modal-open');
    modal.style.display = 'none';
    modal.classList.remove('show');
    currentUserData = null;
}

async function confirmIdentity() {
    if (!currentUserData) return;

    try {
        const response = await fetch(`${API_URL}/tournament/link`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                userId: currentUserData.id,
                deviceId: currentUserData.deviceId,
                username: currentUserData.username
            })
        });

        const data = await response.json();

        if (data.success) {
            currentUserId = currentUserData.id;
            localStorage.setItem('userId', currentUserId);
            closeModal();
            showStatus('success', '✅ ID vinculado com sucesso!');
            checkLinkStatus();
            loadMatches();
        } else {
            showStatus('error', '❌ ' + (data.error || 'Erro ao vincular ID'));
        }
    } catch (err) {
        showStatus('error', '❌ Erro de conexão com o servidor');
        console.error(err);
    }
}

async function checkLinkStatus() {
    if (!currentUserId) return;

    try {
        const response = await fetch(`${API_URL}/tournament/link/user/${currentUserId}`);
        const data = await response.json();

        if (data.linked) {
            showStatus('success', `✅ ID vinculado como: ${data.username}`);
            document.getElementById('link-form').style.display = 'none';
        }
    } catch (err) {
        console.error('Erro ao verificar status:', err);
    }
}

async function loadTournaments() {
    try {
        const response = await fetch(`${API_URL}/tournament/active`);
        const data = await response.json();

        const container = document.getElementById('tournaments-list');

        if (!data.tournaments || data.tournaments.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <div class="empty-state-icon">🏆</div>
                    <p>Nenhum torneio disponível no momento</p>
                </div>
            `;
            return;
        }

        container.innerHTML = data.tournaments.map(t => createTournamentCard(t)).join('');
    } catch (err) {
        console.error('Erro ao carregar torneios:', err);
    }
}

function createTournamentCard(tournament) {
    const statusClass = `status-${tournament.status.replace('_', '-')}`;
    const statusText = {
        'scheduled': 'Agendado',
        'waiting': 'Inscrições Abertas',
        'in_progress': 'Em Andamento',
        'finished': 'Finalizado'
    }[tournament.status] || tournament.status;

    const playersCount = tournament.players ? tournament.players.length : 0;
    const maxPlayers = tournament.maxPlayers || 4;
    const canRegister = (tournament.status === 'waiting') && playersCount < maxPlayers && currentUserId;
    const isRegistered = tournament.players && tournament.players.some(p => p.userId === currentUserId);

    // Calcular timers
    const now = Date.now();
    const regTime = tournament.registrationOpenTime || 0;
    const startTime = tournament.tournamentStartTime || 0;
    
    const regTimer = regTime > now ? formatTimer(regTime - now) : null;
    const startTimer = startTime > now ? formatTimer(startTime - now) : null;

    return `
        <div class="tournament-item">
            <div class="tournament-left">
                <div class="tournament-badge">
                    <div class="tournament-badge-label">${tournament.status === 'finished' ? 'Finalizado' : 'Evento Principal'}</div>
                    ${startTimer ? `<div class="tournament-badge-value">⏱ ${startTimer}</div>` : ''}
                </div>
                
                <div class="tournament-icon">🏆</div>
                
                <div class="tournament-prize">
                    <div class="tournament-prize-label">Prêmio</div>
                    <div class="tournament-prize-value">🎁 Em breve</div>
                </div>
            </div>
            
            <div class="tournament-right">
                <div class="tournament-header">
                    <div class="tournament-name">${tournament.name || 'Torneio'}</div>
                    <span class="tournament-status ${statusClass}">${statusText}</span>
                </div>
                
                <div class="tournament-timeline">
                    <div class="timeline-item">
                        <div class="timeline-dot ${tournament.status !== 'scheduled' ? 'active' : 'inactive'}"></div>
                        <div class="timeline-content">
                            <div class="timeline-label">Inscrições ${tournament.status === 'scheduled' ? 'abrem' : 'abertas'}</div>
                            <div class="timeline-value">
                                ${tournament.registrationTime}
                                ${regTimer ? `<span class="timer">⏱ ${regTimer}</span>` : ''}
                            </div>
                        </div>
                    </div>
                    
                    <div class="timeline-item">
                        <div class="timeline-dot ${tournament.status === 'in_progress' || tournament.status === 'finished' ? 'active' : 'inactive'}"></div>
                        <div class="timeline-content">
                            <div class="timeline-label">Início</div>
                            <div class="timeline-value">
                                ${tournament.startTime}
                                ${startTimer ? `<span class="timer">⏱ ${startTimer}</span>` : ''}
                            </div>
                        </div>
                    </div>
                    
                    <div class="timeline-item">
                        <div class="timeline-dot inactive"></div>
                        <div class="timeline-content">
                            <div class="timeline-label">Fase 1</div>
                            <div class="timeline-value">Rounds ${tournament.rounds || 2}</div>
                        </div>
                    </div>
                    
                    <div class="timeline-item">
                        <div class="timeline-dot ${tournament.status === 'finished' ? 'active' : 'inactive'}"></div>
                        <div class="timeline-content">
                            <div class="timeline-label">Vencedor</div>
                            <div class="timeline-value">${tournament.winner ? tournament.winner.username : 'A definir'}</div>
                        </div>
                    </div>
                </div>
                
                <div class="tournament-details">
                    <div class="detail-item">
                        <div class="detail-label">Estilo</div>
                        <div class="detail-value">${tournament.style || 'N/A'}</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">Emojis</div>
                        <div class="detail-value">${tournament.emojis || 'N/A'}</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">Mapa</div>
                        <div class="detail-value">${tournament.map || 'N/A'}</div>
                    </div>
                </div>

                ${tournament.players && tournament.players.length > 0 ? `
                    <div class="players-list">
                        <h4>Jogadores Inscritos (${playersCount}/${maxPlayers}):</h4>
                        ${tournament.players.map(p => `
                            <span class="player-tag">${p.username || 'Jogador'}${p.eliminated ? ' ❌' : ''}</span>
                        `).join('')}
                    </div>
                ` : ''}

                ${!currentUserId ? `
                    <div class="status-box error">⚠️ Você precisa vincular seu ID para se inscrever</div>
                ` : ''}
                
                ${tournament.status === 'scheduled' && currentUserId ? `
                    <div class="status-box info">⏰ Aguarde a abertura das inscrições</div>
                ` : ''}

                ${canRegister && !isRegistered ? `
                    <button class="btn btn-success" onclick="registerTournament('${tournament.id}')">
                        Inscrever-se
                    </button>
                ` : ''}
                
                ${isRegistered ? `
                    <div class="status-box success">✅ Você está inscrito! Aguarde o início</div>
                ` : ''}
            </div>
        </div>
    `;
}

function formatTimer(ms) {
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    
    if (days > 0) return `${days}d ${hours % 24}h`;
    if (hours > 0) return `${hours}h ${minutes % 60}m`;
    if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
    return `${seconds}s`;
}

async function registerTournament(tournamentId) {
    if (!currentUserId) {
        showStatus('error', '❌ Você precisa vincular seu ID primeiro!');
        return;
    }

    try {
        const response = await fetch(`${API_URL}/tournament/${tournamentId}/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ userId: currentUserId })
        });

        const data = await response.json();

        if (data.success) {
            showStatus('success', '✅ Inscrito com sucesso!');
            loadTournaments();
            loadMatches();
        } else {
            showStatus('error', '❌ ' + (data.error || 'Erro ao se inscrever'));
        }
    } catch (err) {
        showStatus('error', '❌ Erro de conexão');
        console.error(err);
    }
}

async function loadMatches() {
    if (!currentDeviceId) return;

    try {
        const response = await fetch(`${API_URL}/tournament/player/${currentDeviceId}/matches`);
        const data = await response.json();

        const container = document.getElementById('matches-list');

        if (!data.matches || data.matches.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <div class="empty-state-icon">🎮</div>
                    <p>Você não tem partidas pendentes</p>
                </div>
            `;
            return;
        }

        container.innerHTML = data.matches.map(m => createMatchCard(m)).join('');
    } catch (err) {
        console.error('Erro ao carregar partidas:', err);
    }
}

function createMatchCard(match) {
    const player1 = match.players[0];
    const player2 = match.players[1];

    return `
        <div class="match-item">
            <div class="match-header">
                <div>
                    <h3>${match.tournamentName}</h3>
                    <p>Round ${match.round}</p>
                </div>
                <div class="room-code">${match.roomCode}</div>
            </div>

            <div class="vs-container">
                <div class="player-box">
                    <strong>${player1.username}</strong>
                    ${player1.userId === currentUserId ? '<br>👤 VOCÊ' : ''}
                </div>
                <div class="vs-text">VS</div>
                <div class="player-box">
                    <strong>${player2.username}</strong>
                    ${player2.userId === currentUserId ? '<br>👤 VOCÊ' : ''}
                </div>
            </div>

            <div class="status-box info">
                ℹ️ Use o código <strong>${match.roomCode}</strong> para entrar na sala do jogo!
            </div>
        </div>
    `;
}

function showStatus(type, message) {
    const statusBox = document.getElementById('link-status');
    statusBox.className = `status-box ${type}`;
    statusBox.textContent = message;
    statusBox.style.display = 'block';

    setTimeout(() => {
        statusBox.style.display = 'none';
    }, 5000);
}
