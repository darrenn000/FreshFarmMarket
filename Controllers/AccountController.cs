using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using FreshFarmMarket.Models;
using FreshFarmMarket.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using QRCoder;

namespace FreshFarmMarket.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IWebHostEnvironment _environment;
        private readonly ApplicationDbContext _context;
        private readonly IRecaptchaService _recaptchaService;
        private readonly RecaptchaSettings _recaptchaSettings;
        private readonly IEmailService _emailService;
        private readonly IConfiguration _configuration;
        private readonly ILogger<AccountController> _logger;

        public AccountController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IWebHostEnvironment environment,
            ApplicationDbContext context,
            IRecaptchaService recaptchaService,
            IOptions<RecaptchaSettings> recaptchaSettings,
            IEmailService emailService,
            IConfiguration configuration,
            ILogger<AccountController> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _environment = environment;
            _context = context;
            _recaptchaService = recaptchaService;
            _recaptchaSettings = recaptchaSettings.Value;
            _emailService = emailService;
            _configuration = configuration;
            _logger = logger;
        }

        private async Task LogAudit(string userId, string action)
        {
            var auditLog = new AuditLog
            {
                UserId = userId,
                Action = action,
                Timestamp = DateTime.UtcNow,
                IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
                UserAgent = HttpContext.Request.Headers["User-Agent"].ToString()
            };

            _context.AuditLogs.Add(auditLog);
            await _context.SaveChangesAsync();
        }

        [HttpGet]
        public IActionResult Register()
        {
            ViewBag.RecaptchaSiteKey = _recaptchaSettings.SiteKey;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model, string token)
        {
            ViewBag.RecaptchaSiteKey = _recaptchaSettings.SiteKey;

            if (!await _recaptchaService.VerifyToken(token))
            {
                ModelState.AddModelError(string.Empty, "reCAPTCHA verification failed. Please try again.");
                return View(model);
            }

            if (ModelState.IsValid)
            {
                // Handle photo upload
                string uniqueFileName = null;
                if (model.Photo != null)
                {
                    string uploadsFolder = Path.Combine(_environment.WebRootPath, "uploads");
                    uniqueFileName = Guid.NewGuid().ToString() + "_" + model.Photo.FileName;
                    string filePath = Path.Combine(uploadsFolder, uniqueFileName);

                    if (!Directory.Exists(uploadsFolder))
                        Directory.CreateDirectory(uploadsFolder);

                    using (var fileStream = new FileStream(filePath, FileMode.Create))
                    {
                        await model.Photo.CopyToAsync(fileStream);
                    }
                }

                var user = new ApplicationUser
                {
                    UserName = model.Email,
                    Email = model.Email,
                    FullName = model.FullName,
                    CreditCard = model.CreditCard,
                    Gender = model.Gender,
                    PhoneNumber = model.PhoneNumber,
                    DeliveryAddress = model.DeliveryAddress,
                    PostalCode = model.PostalCode,
                    Photo = uniqueFileName,
                    AboutMe = model.AboutMe,
                    LastPasswordChangeDate = DateTime.UtcNow
                };

                var result = await _userManager.CreateAsync(user, model.Password);
                if (result.Succeeded)
                {
                    await _signInManager.SignInAsync(user, isPersistent: false);
                    await LogAudit(user.Id, "User registered");
                    return RedirectToAction("Index", "Home");
                }

                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
            }

            return View(model);
        }

        [HttpGet]
        public IActionResult Login()
        {
            ViewBag.RecaptchaSiteKey = _recaptchaSettings.SiteKey;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string token)
        {
            ViewBag.RecaptchaSiteKey = _recaptchaSettings.SiteKey;

            if (!await _recaptchaService.VerifyToken(token))
            {
                ModelState.AddModelError(string.Empty, "reCAPTCHA verification failed. Please try again.");
                return View(model);
            }

            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user != null)
                {
                    if (user.FailedLoginAttempts >= 3 && user.LockoutEndDate > DateTime.UtcNow)
                    {
                        var remainingTime = user.LockoutEndDate.Value - DateTime.UtcNow;
                        ModelState.AddModelError(string.Empty,
                            $"Account is locked. Please try again after {Math.Ceiling(remainingTime.TotalMinutes)} minutes.");
                        await LogAudit(user.Id, "Login attempt on locked account");
                        return View(model);
                    }

                    var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password,
                        model.RememberMe, lockoutOnFailure: true);
                    if (result.Succeeded)
                    {
                        user.FailedLoginAttempts = 0;
                        user.LockoutEndDate = null;
                        await _userManager.UpdateAsync(user);
                        await LogAudit(user.Id, "User logged in");

                        // Ensure proper authentication
                        await _signInManager.SignInAsync(user, model.RememberMe);

                        return RedirectToAction("Index", "Home");
                    }

                    if (result.IsLockedOut)
                    {
                        ModelState.AddModelError(string.Empty, "Account is locked. Please try again after 15 minutes.");
                        await LogAudit(user.Id, "Account locked out");
                        return View(model);
                    }

                    user.FailedLoginAttempts++;
                    if (user.FailedLoginAttempts >= 3)
                    {
                        user.LockoutEndDate = DateTime.UtcNow.AddMinutes(15);
                        ModelState.AddModelError(string.Empty,
                            $"Too many failed attempts. Account will be locked for 15 minutes.");
                        await LogAudit(user.Id, "Failed login attempt - Account locked");
                    }
                    else
                    {
                        ModelState.AddModelError(string.Empty,
                            $"Invalid login attempt. {3 - user.FailedLoginAttempts} attempts remaining before account lockout.");
                        await LogAudit(user.Id, "Failed login attempt");
                    }
                    await _userManager.UpdateAsync(user);
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                    await LogAudit("Unknown", "Failed login attempt with non-existent account");
                }
            }

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            var userId = _userManager.GetUserId(User);
            await _signInManager.SignOutAsync();
            if (userId != null)
            {
                await LogAudit(userId, "User logged out");
            }
            return RedirectToAction("Login");
        }

        [HttpGet]
        [Authorize]
        public IActionResult ChangePassword()
        {
            return View();
        }

        [HttpPost]
        [Authorize]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
                return RedirectToAction("Login");

            // Check minimum password age
            var minAge = _configuration.GetValue<int>("PasswordPolicy:MinimumAge");
            if (user.LastPasswordChangeDate.HasValue &&
                (DateTime.UtcNow - user.LastPasswordChangeDate.Value).TotalDays < minAge)
            {
                ModelState.AddModelError(string.Empty,
                    $"You must wait {minAge} days before changing your password again.");
                return View(model);
            }

            // Check password history
            var historyLimit = _configuration.GetValue<int>("PasswordPolicy:HistoryLimit");
            var newPasswordHash = _userManager.PasswordHasher.HashPassword(user, model.NewPassword);
            var passwordHistories = await _context.PasswordHistories
                .Where(ph => ph.UserId == user.Id)
                .OrderByDescending(ph => ph.CreatedAt)
                .Take(historyLimit)
                .ToListAsync();

            foreach (var history in passwordHistories)
            {
                if (_userManager.PasswordHasher.VerifyHashedPassword(user, history.PasswordHash, model.NewPassword)
                    != PasswordVerificationResult.Failed)
                {
                    ModelState.AddModelError(string.Empty,
                        "You cannot reuse any of your last 2 passwords.");
                    return View(model);
                }
            }

            var changePasswordResult = await _userManager.ChangePasswordAsync(user,
                model.CurrentPassword, model.NewPassword);
            if (changePasswordResult.Succeeded)
            {
                // Add to password history
                _context.PasswordHistories.Add(new PasswordHistory
                {
                    UserId = user.Id,
                    PasswordHash = newPasswordHash,
                    CreatedAt = DateTime.UtcNow
                });

                user.LastPasswordChangeDate = DateTime.UtcNow;
                await _userManager.UpdateAsync(user);
                await _context.SaveChangesAsync();
                await LogAudit(user.Id, "Password changed");

                await _signInManager.RefreshSignInAsync(user);
                return RedirectToAction("Index", "Home");
            }

            foreach (var error in changePasswordResult.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
            return View(model);
        }

        [HttpGet]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "Please check your email for password reset instructions.");
                return View(model);
            }

            var code = await _userManager.GeneratePasswordResetTokenAsync(user);
            var callbackUrl = Url.Action("ResetPassword", "Account",
                new { email = user.Email, code = code }, protocol: HttpContext.Request.Scheme);

            await _emailService.SendEmailAsync(user.Email, "Reset Password",
                $"Please reset your password by clicking here: <a href='{callbackUrl}'>link</a>");

            await LogAudit(user.Id, "Password reset requested");
            return RedirectToAction("ForgotPasswordConfirmation");
        }

        [HttpGet]
        public IActionResult ResetPassword(string code = null)
        {
            if (code == null)
                return BadRequest("A code must be supplied for password reset.");

            var model = new ResetPasswordViewModel { Code = code };
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "Invalid request.");
                return View(model);
            }

            // Check password history
            var historyLimit = _configuration.GetValue<int>("PasswordPolicy:HistoryLimit");
            var newPasswordHash = _userManager.PasswordHasher.HashPassword(user, model.Password);
            var passwordHistories = await _context.PasswordHistories
                .Where(ph => ph.UserId == user.Id)
                .OrderByDescending(ph => ph.CreatedAt)
                .Take(historyLimit)
                .ToListAsync();

            foreach (var history in passwordHistories)
            {
                if (_userManager.PasswordHasher.VerifyHashedPassword(user, history.PasswordHash, model.Password)
                    != PasswordVerificationResult.Failed)
                {
                    ModelState.AddModelError(string.Empty,
                        "You cannot reuse any of your last 2 passwords.");
                    return View(model);
                }
            }

            var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);
            if (result.Succeeded)
            {
                // Add to password history
                _context.PasswordHistories.Add(new PasswordHistory
                {
                    UserId = user.Id,
                    PasswordHash = newPasswordHash,
                    CreatedAt = DateTime.UtcNow
                });

                user.LastPasswordChangeDate = DateTime.UtcNow;
                await _userManager.UpdateAsync(user);
                await _context.SaveChangesAsync();
                await LogAudit(user.Id, "Password reset completed");

                return RedirectToAction("ResetPasswordConfirmation");
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
            return View(model);
        }

        [HttpGet]
        public IActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        [HttpGet]
        public IActionResult ResetPasswordConfirmation()
        {
            return View();
        }

        [HttpGet]
        [Authorize]
        public async Task<IActionResult> Profile()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
                return RedirectToAction("Login");

            var model = new ProfileViewModel
            {
                FullName = user.FullName,
                Email = user.Email,
                PhoneNumber = user.PhoneNumber,
                DeliveryAddress = user.DeliveryAddress,
                PostalCode = user.PostalCode,
                Photo = user.Photo,
                AboutMe = user.AboutMe,
                TwoFactorEnabled = user.TwoFactorEnabled
            };

            return View(model);
        }

        [HttpPost]
        [Authorize]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Generate2FA()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                _logger.LogWarning("User not found for 2FA generation.");
                return RedirectToAction("Login");
            }

            var unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);
            if (string.IsNullOrEmpty(unformattedKey))
            {
                await _userManager.ResetAuthenticatorKeyAsync(user);
                unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);
                _logger.LogInformation("Generated new 2FA key for user {UserId}", user.Id);
            }

            var qrCodeUrl = $"otpauth://totp/FreshFarmMarket:{user.Email}?secret={unformattedKey}&issuer=FreshFarmMarket&digits=6";
            _logger.LogDebug("Generated QR code URL for user {UserId}: {QrCodeUrl}", user.Id, qrCodeUrl);

            var qrGenerator = new QRCodeGenerator();
            var qrCodeData = qrGenerator.CreateQrCode(qrCodeUrl, QRCodeGenerator.ECCLevel.Q);
            var qrCode = new BitmapByteQRCode(qrCodeData);
            var qrCodeImage = qrCode.GetGraphic(20);
            var qrCodeBase64 = Convert.ToBase64String(qrCodeImage);

            if (string.IsNullOrEmpty(qrCodeBase64))
            {
                _logger.LogError("Failed to generate QR code for user {UserId}.", user.Id);
                ModelState.AddModelError("", "Failed to generate QR code. Please try again.");
                return View("Profile"); // Consider redirecting to an error page or handling this more gracefully
            }

            var model = new ProfileViewModel
            {
                FullName = user.FullName,
                Email = user.Email,
                PhoneNumber = user.PhoneNumber,
                DeliveryAddress = user.DeliveryAddress,
                PostalCode = user.PostalCode,
                Photo = user.Photo,
                AboutMe = user.AboutMe,
                TwoFactorEnabled = user.TwoFactorEnabled,
                SecretKey = unformattedKey,
                QRCodeUrl = $"data:image/png;base64,{qrCodeBase64}"
            };

            return View("Profile", model);
        }


        [HttpPost]
        [Authorize]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Enable2FA(string verificationCode)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                _logger.LogWarning("User not found for enabling 2FA.");
                return RedirectToAction("Login");
            }

            var is2faTokenValid = await _userManager.VerifyTwoFactorTokenAsync(
                user, _userManager.Options.Tokens.AuthenticatorTokenProvider, verificationCode);

            if (!is2faTokenValid)
            {
                _logger.LogWarning("Invalid 2FA token for user {UserId}.", user.Id);
                ModelState.AddModelError("", "Verification code is invalid.");
                return RedirectToAction("Profile");
            }

            await _userManager.SetTwoFactorEnabledAsync(user, true);
            await LogAudit(user.Id, "2FA enabled");
            _logger.LogInformation("2FA enabled for user {UserId}.", user.Id);
            return RedirectToAction("Profile");
        }


        [HttpPost]
        [Authorize]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Disable2FA()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                _logger.LogWarning("User not found for disabling 2FA.");
                return RedirectToAction("Login");
            }

            var disable2faResult = await _userManager.SetTwoFactorEnabledAsync(user, false);
            if (!disable2faResult.Succeeded)
            {
                _logger.LogError("Failed to disable 2FA for user {UserId}.", user.Id);
                ModelState.AddModelError("", "Unexpected error occurred disabling 2FA.");
                return RedirectToAction("Profile");
            }
            _logger.LogInformation("2FA disabled for user {UserId}.", user.Id);
            await LogAudit(user.Id, "2FA disabled");
            return RedirectToAction("Profile");
        }
    }
} 