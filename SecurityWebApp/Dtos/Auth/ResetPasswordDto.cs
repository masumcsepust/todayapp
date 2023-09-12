using System.ComponentModel.DataAnnotations;

namespace SecurityWebApp.Dtos.Auth;
public class ResetPasswordDto
{
    [Required]
    public string Token { get; set; }
    [Required]
    [RegularExpression("^\\w+@[a-zA-Z_]+?\\.[a-zA-Z]{2,3}$", ErrorMessage = "Invalid email address")]
    public string Email { get; set; }

    [Required]
    [StringLength(15, MinimumLength = 3, ErrorMessage = "New password must be at least (3) and maximum (15) characters")] 
    public string NewPassword { get; set; }
}
