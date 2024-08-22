using System.ComponentModel.DataAnnotations;

namespace AuthenticationAuthorization.Models
{
    public class InboundUser
    {
        [Required]
        [EmailAddress]
        public required string Email { get; set; }

        [Required]
        public required string Password { get; set; }
    }
    namespace AuthenticationAuthorization
{
    public enum RoleTypes
    {
        User,
        Admin
    }
}
}

