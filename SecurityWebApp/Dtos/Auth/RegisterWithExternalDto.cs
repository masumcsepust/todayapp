using System.ComponentModel.DataAnnotations;

namespace SecurityWebApp.Dtos.Auth;

public class RegisterWithExternalDto
{
    [Required]
    [StringLength(15, MinimumLength = 3, ErrorMessage = "First name must be at least (2) and maximum (15) characters")]
    public string FirstName { get; set; }
    [Required]
    [StringLength(15, MinimumLength = 3, ErrorMessage = "Last name must be at least (2) and maximum (15) characters")]
    public string LastName { get; set; }

    [Required]
    public string Provider { get; set; }
    [Required]
    public string AccessToken { get; set; }
    [Required]
    public string UserId { get; set; }
}
