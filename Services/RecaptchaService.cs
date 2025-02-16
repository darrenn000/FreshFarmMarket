using System.Net.Http;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;
using FreshFarmMarket.Models;

namespace FreshFarmMarket.Services
{
    public interface IRecaptchaService
    {
        Task<bool> VerifyToken(string token);
    }

    public class RecaptchaService : IRecaptchaService
    {
        private readonly RecaptchaSettings _settings;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly ILogger<RecaptchaService> _logger;

        public RecaptchaService(
            IOptions<RecaptchaSettings> settings, 
            IHttpClientFactory httpClientFactory,
            ILogger<RecaptchaService> logger)
        {
            _settings = settings.Value;
            _httpClientFactory = httpClientFactory;
            _logger = logger;
        }

        public async Task<bool> VerifyToken(string token)
        {
            if (string.IsNullOrEmpty(token))
            {
                _logger.LogWarning("reCAPTCHA token is empty");
                return false;
            }

            try
            {
                var client = _httpClientFactory.CreateClient();
                var response = await client.GetStringAsync($"https://www.google.com/recaptcha/api/siteverify?secret={_settings.SecretKey}&response={token}");
                
                _logger.LogInformation($"reCAPTCHA API Response: {response}");

                var options = new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                };
                
                var recaptchaResponse = JsonSerializer.Deserialize<RecaptchaResponse>(response, options);
                
                if (recaptchaResponse == null)
                {
                    _logger.LogError("Failed to deserialize reCAPTCHA response");
                    return false;
                }

                // Log full response for debugging
                _logger.LogInformation($"Deserialized Response - Success: {recaptchaResponse.Success}, Score: {recaptchaResponse.Score}, Action: {recaptchaResponse.Action}");

                if (!recaptchaResponse.Success)
                {
                    if (recaptchaResponse.ErrorCodes != null && recaptchaResponse.ErrorCodes.Length > 0)
                    {
                        var errorCodes = string.Join(", ", recaptchaResponse.ErrorCodes);
                        _logger.LogWarning($"reCAPTCHA verification failed with error codes: {errorCodes}");
                    }
                    else
                    {
                        _logger.LogWarning("reCAPTCHA verification failed without error codes");
                    }
                    return false;
                }

                if (recaptchaResponse.Score < _settings.MinimumScore)
                {
                    _logger.LogWarning($"reCAPTCHA score too low: {recaptchaResponse.Score} (minimum: {_settings.MinimumScore})");
                    return false;
                }

                var validActions = new[] { "register", "login" };
                if (string.IsNullOrEmpty(recaptchaResponse.Action) || !validActions.Contains(recaptchaResponse.Action.ToLower()))
                {
                    _logger.LogWarning($"reCAPTCHA action mismatch. Expected: register/login, Got: {recaptchaResponse.Action ?? "null"}");
                    return false;
                }

                _logger.LogInformation($"reCAPTCHA verification successful. Score: {recaptchaResponse.Score}, Action: {recaptchaResponse.Action}");
                return true;
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError(ex, "HTTP request to reCAPTCHA API failed");
                return false;
            }
            catch (JsonException ex)
            {
                _logger.LogError(ex, "Failed to parse reCAPTCHA response");
                return false;
            }
        }

        private class RecaptchaResponse
        {
            public bool Success { get; set; }
            public double Score { get; set; }
            public string Action { get; set; }
            public string Hostname { get; set; }
            public string[] ErrorCodes { get; set; }
        }
    }
} 