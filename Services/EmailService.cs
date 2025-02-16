using System;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;

namespace FreshFarmMarket.Services
{
	public interface IEmailService
	{
		Task SendEmailAsync(string email, string subject, string message);
	}

	public class EmailService : IEmailService
	{
		private readonly EmailSettings _emailSettings;
		private readonly ILogger<EmailService> _logger; // Logger instance

		public EmailService(IOptions<EmailSettings> emailSettings, ILogger<EmailService> logger)
		{
			_emailSettings = emailSettings.Value;
			_logger = logger;
		}

		public async Task SendEmailAsync(string email, string subject, string message)
		{
			var emailMessage = new MimeMessage();
			emailMessage.From.Add(new MailboxAddress(_emailSettings.SenderName, _emailSettings.SenderEmail));
			emailMessage.To.Add(new MailboxAddress("", email));
			emailMessage.Subject = subject;
			emailMessage.Body = new TextPart("html") { Text = message };

			using (var client = new SmtpClient())
			{
				try
				{
					await client.ConnectAsync(_emailSettings.SmtpServer, _emailSettings.SmtpPort, SecureSocketOptions.StartTls);
					await client.AuthenticateAsync(_emailSettings.SmtpUsername, _emailSettings.SmtpPassword);
					await client.SendAsync(emailMessage);
					_logger.LogInformation("Email successfully sent to {Email}", email);
				}
				catch (Exception ex)
				{
					_logger.LogError(ex, "Error sending email to {Email}", email);
					throw;  // Rethrow the exception after logging it, or handle it if appropriate
				}
				finally
				{
					await client.DisconnectAsync(true);
					_logger.LogInformation("SMTP client disconnected.");
				}
			}
		}
	}

	public class EmailSettings
	{
		public string SmtpServer { get; set; }
		public int SmtpPort { get; set; }
		public string SmtpUsername { get; set; }
		public string SmtpPassword { get; set; }
		public string SenderEmail { get; set; }
		public string SenderName { get; set; }
	}
}
