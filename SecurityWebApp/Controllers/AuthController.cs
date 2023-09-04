using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SecurityWebApp.Dtos.Auth;
using SecurityWebApp.Models;
using SecurityWebApp.Services;
using System.Security.Claims;
using System.Threading.Tasks;

namespace SecurityWebApp.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly JWTService _jWTService;
    private readonly UserManager<User> _userManager;
    private readonly SignInManager<User> _signInManager;

    public AuthController(JWTService jWTService
        , UserManager<User> userManager
        , SignInManager<User> signInManager)
    {
        _jWTService = jWTService;
        _userManager = userManager;
        _signInManager = signInManager;
    }

    [HttpPost("login")]
    public async Task<ActionResult<UserDto>> Login(LoginDto model)
    {
        var user = await _userManager.FindByNameAsync(model.UserName);
        if (user is null) return Unauthorized("invalid username or password");

        if (user.EmailConfirmed == false) return Unauthorized("please confirm your email.");

        var result = await _signInManager.CheckPasswordSignInAsync(user, model.Password, false);
        if (!result.Succeeded) return Unauthorized("Invalid username or password.");
        return CreateApplicationUserDto(user);
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterDto model)
    {
        if (await CheckEmailExistsAsync(model.Email)) return BadRequest($"email {model.Email} already exists");
        var userToAdd = new User
        {
            FirstName = model.FirstName.ToLower(),
            LastName = model.LastName.ToLower(),
            UserName = model.Email.ToLower(),
            Email = model.Email.ToLower(),
            EmailConfirmed = true
        };

        var result = await _userManager.CreateAsync(userToAdd, model.Password);
        if (!result.Succeeded) return BadRequest(result.Errors);

        return Ok("your account has been created");
    }

    [Authorize]
    [HttpGet("refresh-user-token")]
    public async Task<ActionResult<UserDto>> RefreshUserToken()
    {
        var user = await _userManager.FindByNameAsync(User.FindFirst(ClaimTypes.Email)?.Value);
        return CreateApplicationUserDto(user);
    }
    private UserDto CreateApplicationUserDto(User user)
    {
        return new UserDto
        {
            FirstName = user.FirstName,
            LastName = user.LastName,
            JWT = _jWTService.CreateJWT(user)
        };
    }
    
    private async Task<bool> CheckEmailExistsAsync(string email)
    {
        return await _userManager.Users.AnyAsync(x => x.Email == email.ToLower()); 
    }
}
