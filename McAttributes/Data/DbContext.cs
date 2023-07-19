using McAttributes.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace McAttributes.Data
{
    public class IdDbContext : DbContext
    {
        public IdDbContext(DbContextOptions<IdDbContext> options)
            : base(options) { }

        public DbSet<User>? Users { get; set; }

        public DbSet<EmployeeIdRecord>? EmployeeIds { get; set; }

        public DbSet<Stargate>? Stargate { get; set; }


        protected override void OnModelCreating(ModelBuilder builder)
        {
            builder.Entity<IssueLogEntry>(entity => {
                entity.Property(p => p.Created).HasDefaultValue(DateTime.UtcNow)
                    .Metadata.SetAfterSaveBehavior(PropertySaveBehavior.Throw);
            });

            //builder.Entity<EmployeeIdRecord>().Property(e => e.ConcurrencyId)
            //    .ForNpgsqlHasColumnName("xmin")
            //    .ForNpgsqlHasColumnType("xid")
            //    .ValueGeneratedOnAddOrUpdate()
            //    .IsConcurrencyToken();

            //// AadId should be unique
            //builder.Entity<IssueLogEntry>()
            //    .ForNpgsqlUseXminAsConcurrencyToken()
            //    .HasIndex(u => u.AlertHash)
            //    .IsUnique();

            //// AadId should be unique
            //builder.Entity<User>()
            //    .ForNpgsqlUseXminAsConcurrencyToken()
            //    .HasIndex(u => u.AadId)
            //    .IsUnique();

            //// Index Mail and EmployeeId
            //builder.Entity<User>()
            //    .ForNpgsqlUseXminAsConcurrencyToken()
            //    .HasIndex(u => u.Mail)
            //    .HasIndex(u => u.EmployeeId);
        }
    }
}
