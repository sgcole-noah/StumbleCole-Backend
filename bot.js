import { Client, GatewayIntentBits } from "discord.js";
import dotenv from "dotenv";
dotenv.config();

const bot = new Client({
    intents: [GatewayIntentBits.Guilds]
});

bot.once("ready", () => {
    console.log(`Bot online als ${bot.user.tag}`);
});

bot.login(process.env.BOT_API_KEY);
