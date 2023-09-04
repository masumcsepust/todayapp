using System.ComponentModel.DataAnnotations;

namespace SecurityWebApp.Dtos.Auth;
public class RegisterDto
{
    [Required]
    [StringLength(15, MinimumLength = 3, ErrorMessage = "First name must be at least (2) and maximum (15) characters")]
    public string FirstName { get; set; }
    [Required]
    [StringLength(15, MinimumLength = 3, ErrorMessage = "Last name must be at least (2) and maximum (15) characters")]
    public string LastName { get; set; }
    [Required]
    [RegularExpression("^\\w+@[a-zA-Z_]+?\\.[a-zA-Z]{2,3}$", ErrorMessage = "Invalid email address")]
    public string Email { get; set; }

    [Required]
    [StringLength(15, MinimumLength = 3, ErrorMessage = "Password must be at least (2) and maximum (15) characters")]
    public string Password { get; set; }
}
