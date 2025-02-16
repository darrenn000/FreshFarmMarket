namespace FreshFarmMarket.Models
{
    public class RecaptchaSettings
    {
        public string SiteKey { get; set; }
        public string SecretKey { get; set; }
        public string Version { get; set; }
        public double MinimumScore { get; set; }
    }
} 