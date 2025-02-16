using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace FreshFarmMarket.Models
{
    public class AuditLog
    {
        public int Id { get; set; }
        public string UserId { get; set; }
        public string Action { get; set; }
        public DateTime Timestamp { get; set; }
        public string IpAddress { get; set; }
        public string UserAgent { get; set; }
    }

    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public DbSet<AuditLog> AuditLogs { get; set; }
        public DbSet<PasswordHistory> PasswordHistories { get; set; }

        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            
            // Configure AuditLog
            builder.Entity<AuditLog>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Action).IsRequired();
                entity.Property(e => e.Timestamp).IsRequired();
            });

            // Configure ApplicationUser
            builder.Entity<ApplicationUser>(entity =>
            {
                // Configure CreditCard to use backing field
                entity.Property(e => e.CreditCard)
                    .HasField("_creditCard")
                    .HasMaxLength(200);

                // Configure DeliveryAddress to use backing field
                entity.Property(e => e.DeliveryAddress)
                    .HasField("_deliveryAddress")
                    .HasMaxLength(250);

                // Configure password history relationship
                entity.HasMany(e => e.PasswordHistories)
                    .WithOne()
                    .HasForeignKey(e => e.UserId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            // Configure PasswordHistory
            builder.Entity<PasswordHistory>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.PasswordHash).IsRequired();
                entity.Property(e => e.CreatedAt).IsRequired();
            });
        }

        // Add your DbSet properties here for your models
    }
} 