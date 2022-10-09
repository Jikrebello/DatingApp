using System.ComponentModel.DataAnnotations;

namespace API.DTOs
{
    public class RegisterDto
    {
        [Required]
        public string UserName { get; set; }

        [Required]
        [StringLength(maximumLength: 8, MinimumLength = 4)]
        public string Password { get; set; }
    }
}
