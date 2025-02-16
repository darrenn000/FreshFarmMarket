using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;

namespace FreshFarmMarket.Models
{
    public class ApplicationUser : IdentityUser
    {
        private string? _creditCard;
        private string? _deliveryAddress;
        private static readonly string _encryptionKey;
        private static readonly byte[] _initializationVector;

        // Password history and age policies
        public List<PasswordHistory> PasswordHistories { get; set; } = new List<PasswordHistory>();
        public DateTime? LastPasswordChangeDate { get; set; }
        public bool TwoFactorEnabled { get; set; }
        public string? TwoFactorSecretKey { get; set; }

        static ApplicationUser()
        {
            var configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json")
                .Build();

            _encryptionKey = configuration["EncryptionSettings:Key"] ?? "YourSecureEncryptionKey123!@#$%^&*()";
            // Use a fixed IV for consistency (in a real-world app, you might want to use a different approach)
            _initializationVector = new byte[16] { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };
        }

        [Required]
        [StringLength(100)]
        public string FullName { get; set; } = null!;

        [Required]
        [StringLength(200)]
        public string CreditCard
        {
            get => DecryptData(_creditCard ?? string.Empty);
            set => _creditCard = EncryptData(value);
        }

        [Required]
        public string Gender { get; set; } = null!;

        [Required]
        [RegularExpression(@"^\d{8,14}$", ErrorMessage = "Mobile number must be between 8 and 14 digits")]
        public override string PhoneNumber { get; set; } = null!;

        [Required]
        [StringLength(250)]
        public string DeliveryAddress
        {
            get => DecryptData(_deliveryAddress ?? string.Empty);
            set => _deliveryAddress = EncryptData(value);
        }

        [Required]
        [StringLength(6)]
        public string PostalCode { get; set; } = null!;

        [Required]
        public string Photo { get; set; } = null!;

        [Required]
        public string AboutMe { get; set; } = null!;

        public int FailedLoginAttempts { get; set; }
        public DateTime? LockoutEndDate { get; set; }

        private static string EncryptData(string data)
        {
            if (string.IsNullOrEmpty(data)) return data;
            
            try
            {
                byte[] key = Encoding.UTF8.GetBytes(_encryptionKey);
                // Ensure the key is exactly 32 bytes (256 bits)
                if (key.Length != 32)
                {
                    Array.Resize(ref key, 32);
                }

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = _initializationVector;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    using (MemoryStream memoryStream = new MemoryStream())
                    {
                        using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                        using (StreamWriter streamWriter = new StreamWriter(cryptoStream))
                        {
                            streamWriter.Write(data);
                        }

                        return Convert.ToBase64String(memoryStream.ToArray());
                    }
                }
            }
            catch (Exception ex)
            {
                // Log the error in production
                throw new Exception("Encryption failed", ex);
            }
        }

        private static string DecryptData(string encryptedData)
        {
            if (string.IsNullOrEmpty(encryptedData)) return encryptedData;
            
            try
            {
                byte[] key = Encoding.UTF8.GetBytes(_encryptionKey);
                // Ensure the key is exactly 32 bytes (256 bits)
                if (key.Length != 32)
                {
                    Array.Resize(ref key, 32);
                }

                byte[] cipherText = Convert.FromBase64String(encryptedData);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = _initializationVector;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    using (MemoryStream memoryStream = new MemoryStream(cipherText))
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    using (StreamReader streamReader = new StreamReader(cryptoStream))
                    {
                        return streamReader.ReadToEnd();
                    }
                }
            }
            catch (Exception ex)
            {
                // Log the error in production
                throw new Exception("Decryption failed", ex);
            }
        }
    }

    public class PasswordHistory
    {
        public int Id { get; set; }
        public string UserId { get; set; }
        public string PasswordHash { get; set; }
        public DateTime CreatedAt { get; set; }
    }
} 