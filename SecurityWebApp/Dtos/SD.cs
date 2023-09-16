using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace SecurityWebApp.Dtos;
public static class SD
{
    public static string Facebook { get; set; } = "facebook";
    public static string Google { get; set; } = "google";
    public static string Admin { get; set; } = "admin";
    public static string Manager { get; set; } = "manager";
    public static string Player { get; set; } = "player";

    public static bool VIPPolicy(AuthorizationHandlerContext context)
    {
        if(context.User.IsInRole(Player) &&
            context.User.HasClaim(c => c.Type == ClaimTypes.Email && c.Value.Contains("vip")))
        {
            return true;
        }

        return false;
    }
}
