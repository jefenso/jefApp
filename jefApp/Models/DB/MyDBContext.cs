using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;

namespace jefApp.Models.DB
{
    public class MyDBContext : DbContext
    {
        public MyDBContext()
        {
        }

        public MyDBContext(DbContextOptions<MyDBContext> options)
           : base(options)
        {
        }

        public virtual DbSet<Users> Users { get; set; }
        public virtual DbSet<SystemUsers> SystemUsers { get; set; }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            if (!optionsBuilder.IsConfigured)
            {
                // warning To protect potentially sensitive information in your connection string,
                // you should move it out of source code.See http://go.microsoft.com/fwlink/?LinkId=723263
                // for guidance on storing connection strings.
                optionsBuilder.UseSqlServer("Data Source=(localdb)\\MyDemoDB;Initial Catalog=jDB;Integrated Security=True;Multiple Active Result Sets=True");
            }
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<Users>(entity =>
            {
                entity.ToTable("SYSUserProfile");

                entity.Property(e => e.ProfileID)
                .HasColumnName("SYSUserProfileID")

                .HasColumnType("int");

                entity.Property(e => e.UserID)
                .HasColumnName("SYSUserID")
                .HasColumnType("int");

                entity.Property(e => e.FirstName)
                .HasColumnName("FirstName")
                .HasMaxLength(50)
                .IsUnicode(false);

                entity.Property(e => e.LastName)
                .HasColumnName("LastName")
                .HasMaxLength(50)
                .IsUnicode(false);

                entity.Property(e => e.Gender)
                  .HasColumnName("Gender")
                  .HasColumnType("char(1)");

                entity.Property(e => e.CreatedBy)
                  .HasColumnName("RowCreatedSYSUserID")
                  .HasColumnType("int");

                entity.Property(e => e.CreatedDateTime)
                  .HasColumnName("RowCreatedDateTime")
                  .HasDefaultValueSql("CURRENT_TIMESTAMP");

                entity.Property(e => e.ModifiedBy)
                  .HasColumnName("RowModifiedSYSUserID")
                  .HasColumnType("int");

                entity.Property(e => e.ModifiedDateTime)
                  .HasColumnName("RowModifiedDateTime")
                  .HasDefaultValueSql("CURRENT_TIMESTAMP");

                entity.Property(e => e.AccountImage)
                .HasColumnName("AccountImage")
                .IsUnicode(false);


            });

            modelBuilder.Entity<SystemUsers>(entity =>
            {
                entity.ToTable("SYSUser");

                entity.Property(e => e.UserID)
                .HasColumnName("SYSUserID")
                .HasColumnType("int");

                entity.Property(e => e.LoginName)
                .HasColumnName("LoginName")
                .HasMaxLength(50)
                .IsUnicode(false);

                entity.Property(e => e.CreatedBy)
                  .HasColumnName("RowCreatedSYSUserID")
                  .HasColumnType("int");

                entity.Property(e => e.CreatedDateTime)
                  .HasColumnName("RowCreatedDateTime")
                  .HasDefaultValueSql("CURRENT_TIMESTAMP");

                entity.Property(e => e.ModifiedBy)
                  .HasColumnName("RowModifiedSYSUserID")
                  .HasColumnType("int");

                entity.Property(e => e.ModifiedDateTime)
                  .HasColumnName("RowModifiedDateTime")
                  .HasDefaultValueSql("CURRENT_TIMESTAMP");

            });

            

        }
    }
}
