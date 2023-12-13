using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace McAttributes.Models
{
    [Table("employeeidrecord")]
    public class EmployeeIdRecord
    {
        [Key]
        public int Id { get; set; }
        public string? CloudSourceAnchor { get; init; }
        public string? UserPrincipalName { get; init; }
        public string? EmployeeId { get; set; }
        public string? AdEmployeeId { get; set; }

        [Column("xmin")]
        public uint ConcurrencyId { get; set; }
    }
}
