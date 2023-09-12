using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace SecurityWebApp.Controllers;

[Route("api/[controller]")]
[ApiController]
[Authorize]
public class PlayController : ControllerBase
{
    [HttpGet]
    public IActionResult Players()
    {
        return Ok(new JsonResult(new { Message = "only authorize can view"}));
    }
}
