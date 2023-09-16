using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace SecurityWebApp.Controllers;

[Route("api/[controller]")]
[ApiController]
public class RCPracticeController : ControllerBase
{
    [HttpGet("public")]
    public IActionResult Public()
    {
        return Ok("public");
    }
    #region Roles
    [HttpGet("admin-role")]
    [Authorize(Roles = "admin")]
    public IActionResult AdminRole()
    {
        return Ok("admin-role");
    }
    [HttpGet("manager-role")]
    [Authorize(Roles = "manager")]
    public IActionResult ManagerRole()
    {
        return Ok("manager-role");
    }
    [HttpGet("player-role")]
    [Authorize(Roles = "player")]
    public IActionResult PlayerRole()
    {
        return Ok("player-role");
    }
    [HttpGet("admin-or-manager-role")]
    [Authorize(Roles = "admin,manager")]
    public IActionResult AdminManagerRole()
    {
        return Ok("admin-manager-role");
    }
    [HttpGet("admin-or-player-role")]
    [Authorize(Roles = "admin,player")]
    public IActionResult AdminPlayerRole()
    {
        return Ok("admin-player-role");
    }

    [HttpGet("vip-player-role")]
    [Authorize(Roles = "player")]
    public IActionResult VipPlayerRole()
    {
        return Ok("vip-player-role");
    }
    #endregion

    #region
    [HttpGet("admin-policy")]
    [Authorize(policy: "admin")]
    public IActionResult AdminPolicy()
    {
        return Ok("admin-policy");
    }
    [HttpGet("manager-policy")]
    [Authorize(policy: "manager")]
    public IActionResult ManagerPolicy()
    {
        return Ok("manager-policy");
    }
    [HttpGet("player-policy")]
    [Authorize(policy: "player")]
    public IActionResult PlayerPolicy()
    {
        return Ok("player-policy");
    }
    [HttpGet("admin-or-manager-policy")]
    [Authorize(policy: "admin-or-manager")]
    public IActionResult AdminManagerPolicy()
    {
        return Ok("admin-or-manager-policy");
    }
    [HttpGet("admin-or-player-policy")]
    [Authorize(policy: "admin-or-player")]
    public IActionResult AdminPlayerPolicy()
    {
        return Ok("admin-or-player-policy");
    }
    [HttpGet("vipplayer-policy")]
    [Authorize(policy: "player")]
    public IActionResult VipPlayerPolicy()
    {
        return Ok("vip-player-policy");
    }
    #endregion

    #region claim policy
    [HttpGet("admin-email-policy")]
    [Authorize(policy: "admin-email-policy")]
    public IActionResult AdminEmailPolicy()
    {
        return Ok("admin-email-policy");
    }

    [HttpGet("ullah-surname-policy")]
    [Authorize(policy: "ullah-surname-policy")]
    public IActionResult UllahSurnamePlayerPolicy()
    {
        return Ok("ullah-surname-policy");
    }

    [HttpGet("vip-policy")]
    [Authorize(policy: "VIPPolicy")]
    public IActionResult VIPPolicy()
    {
        return Ok("vip-policy");
    }
    #endregion
}
