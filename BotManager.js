// BotManager.js
const { Client, GatewayIntentBits } = require('discord.js');

class BotManager {
    constructor() {
        this.client = new Client({ intents: [GatewayIntentBits.Guilds] });
    }

    init() {
        this.client.once('ready', () => {
            console.log('Bot ist online!');
        });
        
        // Nutze eine Umgebungsvariable für den Token
        this.client.login(process.env.DISCORD_TOKEN);
    }
}

module.exports = new BotManager();
