// Exemplo de integração do cliente C# com o sistema de bot Discord
// Este código deve ser adicionado ao seu cliente MelonLoader

using System;
using System.Collections;
using System.Net.Http;
using System.Text;
using UnityEngine;
using Newtonsoft.Json;

public class BotIntegration
{
    private static readonly HttpClient httpClient = new HttpClient();
    private static string backendUrl = "http://seu-backend-url.com"; // Altere para o URL do seu backend
    private static string currentUserId = null;
    private static bool isRegistered = false;

    // Chamar este método quando o jogador fizer login
    public static IEnumerator RegisterClient(string userId, string deviceId)
    {
        currentUserId = userId ?? deviceId;
        
        var data = new
        {
            userId = userId,
            deviceId = deviceId
        };

        string json = JsonConvert.SerializeObject(data);
        var content = new StringContent(json, Encoding.UTF8, "application/json");

        var request = new HttpRequestMessage(HttpMethod.Post, $"{backendUrl}/client/register")
        {
            Content = content
        };

        HttpResponseMessage response = null;
        
        try
        {
            var task = httpClient.SendAsync(request);
            while (!task.IsCompleted)
            {
                yield return null;
            }
            
            response = task.Result;
            
            if (response.IsSuccessStatusCode)
            {
                isRegistered = true;
                Debug.Log("[BotIntegration] Cliente registrado com sucesso");
                
                // Iniciar listener para comandos do bot
                MelonLoader.MelonCoroutines.Start(ListenForBotCommands());
            }
            else
            {
                Debug.LogError($"[BotIntegration] Erro ao registrar cliente: {response.StatusCode}");
            }
        }
        catch (Exception ex)
        {
            Debug.LogError($"[BotIntegration] Exceção ao registrar: {ex.Message}");
        }
    }

    // Chamar este método quando o jogador sair/desconectar
    public static IEnumerator UnregisterClient()
    {
        if (!isRegistered || string.IsNullOrEmpty(currentUserId))
        {
            yield break;
        }

        var data = new
        {
            userId = currentUserId
        };

        string json = JsonConvert.SerializeObject(data);
        var content = new StringContent(json, Encoding.UTF8, "application/json");

        var request = new HttpRequestMessage(HttpMethod.Post, $"{backendUrl}/client/unregister")
        {
            Content = content
        };

        try
        {
            var task = httpClient.SendAsync(request);
            while (!task.IsCompleted)
            {
                yield return null;
            }
            
            isRegistered = false;
            Debug.Log("[BotIntegration] Cliente desregistrado");
        }
        catch (Exception ex)
        {
            Debug.LogError($"[BotIntegration] Erro ao desregistrar: {ex.Message}");
        }
    }

    // Listener para comandos do bot (polling simples)
    private static IEnumerator ListenForBotCommands()
    {
        while (isRegistered)
        {
            // Aguardar 5 segundos entre verificações
            yield return new WaitForSeconds(5f);

            // Aqui você pode implementar um sistema de polling ou WebSocket
            // para receber comandos do bot em tempo real
            
            // Exemplo: verificar se há comando de kick pendente
            // Se houver, executar Application.Quit() ou similar
        }
    }

    // Método para forçar desconexão (chamado pelo comando /kick)
    public static void ForceDisconnect(string reason)
    {
        Debug.LogWarning($"[BotIntegration] Desconexão forçada: {reason}");
        
        // Mostrar modal de aviso
        ShowMaintenanceModal(reason);
        
        // Aguardar 3 segundos e fechar o jogo
        MelonLoader.MelonCoroutines.Start(DelayedQuit(3f));
    }

    private static IEnumerator DelayedQuit(float delay)
    {
        yield return new WaitForSeconds(delay);
        Application.Quit();
    }

    // Método para mostrar modal de manutenção
    public static void ShowMaintenanceModal(string message)
    {
        // Implementar UI modal aqui
        // Similar ao modal de atualização disponível, mas sem botão OK
        Debug.Log($"[BotIntegration] Modal de manutenção: {message}");
        
        // Exemplo de implementação:
        // GameObject modal = GameObject.Instantiate(maintenanceModalPrefab);
        // modal.GetComponentInChildren<Text>().text = message;
    }
}

// ============================================
// EXEMPLO DE USO NO SEU CÓDIGO PRINCIPAL
// ============================================

public class YourMainClass : MelonLoader.MelonMod
{
    public override void OnApplicationStart()
    {
        // Seu código de inicialização
    }

    // Quando o jogador fizer login
    private void OnPlayerLogin(string userId, string deviceId)
    {
        // Registrar cliente no sistema de bot
        MelonLoader.MelonCoroutines.Start(BotIntegration.RegisterClient(userId, deviceId));
    }

    // Quando o jogador sair
    private void OnPlayerLogout()
    {
        // Desregistrar cliente
        MelonLoader.MelonCoroutines.Start(BotIntegration.UnregisterClient());
    }

    // Quando receber resposta de login do backend
    private void OnLoginResponse(string response)
    {
        // Verificar se está em manutenção
        if (response.Contains("\"maintenance\":true"))
        {
            BotIntegration.ShowMaintenanceModal("O servidor está em manutenção. Tente novamente mais tarde.");
            return;
        }

        // Processar login normalmente
        // ...
    }
}
