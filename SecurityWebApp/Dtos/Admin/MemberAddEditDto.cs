using System.ComponentModel.DataAnnotations;

namespace SecurityWebApp.Dtos.Admin;
public class MemberAddEditDto
{
    [Required]
    public string Id { get; set; }
    [Required]
    public string UserName { get; set; }
    [Required]
    public string FirstName { get; set; }
    [Required]
    public string LastName { get; set; }
    [Required]
    public string Password { get; set; }
    public string Roles { get; set; }
}
