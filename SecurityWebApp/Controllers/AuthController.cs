using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using SecurityWebApp.Dtos;
using SecurityWebApp.Dtos.Auth;
using SecurityWebApp.Models;
using SecurityWebApp.Services;
using System;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace SecurityWebApp.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly JWTService _jWTService;
    private readonly UserManager<User> _userManager;
    private readonly SignInManager<User> _signInManager;
    private readonly IConfiguration _config;
    private readonly EmailService _emailService;

    public AuthController(JWTService jWTService
        , UserManager<User> userManager
        , SignInManager<User> signInManager
        , IConfiguration config
        , EmailService emailService)
    {
        _jWTService = jWTService;
        _userManager = userManager;
        _signInManager = signInManager;
        _config = config;
        _emailService = emailService;
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
            Email = model.Email.ToLower()
        };

        var result = await _userManager.CreateAsync(userToAdd, model.Password);
        if (!result.Succeeded) return BadRequest(result.Errors);

        try
        {
            if(await SendConfirmEmailAsync(userToAdd))
            {
                return Ok(new JsonResult(new { Title = "Account created", Message = "Your account has been created, please confirm your mail." }));
            }

            return BadRequest("failed to send email. please contact admin");
        }
        catch (Exception)
        {
            return BadRequest("failed to send email. please contact admin");
        }
    }

    [Authorize]
    [HttpGet("refresh-user-token")]
    public async Task<ActionResult<UserDto>> RefreshUserToken()
    {
        var user = await _userManager.FindByNameAsync(User.FindFirst(ClaimTypes.Email)?.Value);
        return CreateApplicationUserDto(user);
    }

    [HttpPut("confirm-email")]
    public async Task<IActionResult> ConfirmEmail(ConfirmEmailDto confirmEmailDto)
    {
        var user = await _userManager.FindByEmailAsync(confirmEmailDto.Email);
        if (user == null) return Unauthorized("this email address has not been register yet.");

        if (user.EmailConfirmed) return BadRequest("Your email was confirm before. please login to your account");

        try
        {
            var decodedTokenBytes = WebEncoders.Base64UrlDecode(confirmEmailDto.Token);
            var decodedToken = Encoding.UTF8.GetString(decodedTokenBytes);

            var result = await _userManager.ConfirmEmailAsync(user, decodedToken);

            if (result.Succeeded)
            {
                return Ok(new JsonResult(new { Title = "Email Confirm", Message = "your email address is confirm" }));
            }

            return BadRequest("Invalid token please try again");
        }
        catch (Exception)
        {
            return BadRequest("Invalid token please try again");
        }
    }
    [HttpPost("resend-email-confirmation-link/{email}")]
    public async Task<IActionResult> ResendEmailConfirmationLink(string email)
    {
        if (string.IsNullOrEmpty(email)) return BadRequest("Invalid email.");
        var user = await _userManager.FindByEmailAsync(email);
        
        if (user == null) return Unauthorized("This email address has not been registered yet");
        if (user.EmailConfirmed) return BadRequest("Your email address was confirmed before. Please login to your account.");

        try
        {
            if (await SendConfirmEmailAsync(user))
                return Ok(new JsonResult(new { Title = "Confirmation link sent", message = "Please confirm you email address" }));

            return BadRequest("failed to send email. Please contact admin");
        }
        catch(Exception) 
        { 
            return BadRequest("failed to send email. Please contact admin"); 
        }

    }

    [HttpPost("forgot-username-or-password/{email}")]
    public async Task<IActionResult> ForgotUsernameOrPassword(string email)
    {
        if (string.IsNullOrEmpty(email)) return BadRequest("Invalid email");
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null) return BadRequest("This email is not register yet");
        if (!user.EmailConfirmed) return BadRequest("Please confirm your email address first.");

        try
        {
            if (await SendForgotUsernameOrPasswordEmail(user))
                return Ok(new JsonResult(new { Title = "Forgot username or password email sent", Message = "Please check your email" }));

            return BadRequest("Failed to send email. Please contact admin");
        }
        catch(Exception)
        {
            return BadRequest("Failed to send email. Please contact admin");
        }
    }

    [HttpPut("reset-password")]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDto model)
    {
        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null) return Unauthorized("please confirm your email address first.");

        if (!user.EmailConfirmed) return BadRequest("Your email was confirm before. please login to your account");

        try
        {
            var decodedTokenBytes = WebEncoders.Base64UrlDecode(model.Token);
            var decodedToken = Encoding.UTF8.GetString(decodedTokenBytes);

            var result = await _userManager.ResetPasswordAsync(user, decodedToken, model.NewPassword);
            if(result.Succeeded)
                return Ok(new JsonResult(new { Title="password reset success", message="your password has been reset."}));

            return BadRequest("Invalid token. Please try again");
        }
        catch(Exception)
        {
            return BadRequest("Invalid token. Please try again");
        }
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

    private async Task<bool> SendConfirmEmailAsync(User user)
    {
        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
        var url = $"{_config["JWT:ClientUrl"]}/{_config["Email:ConfirmEmailPath"]}?token={token}&email={user.Email}";
        var body = $"<p> hello: {user.FirstName} {user.LastName}" +
                "<p>Please confirm your email address by clicking on the following link.</p>" +
                $"<p><a href=\"{url}\">Click here</a>" +
                "<p>Thank you,</p>" +
                $"<br>{_config["Email:ApplicationName"]}";

        var emailSend = new EmailSendDto(user.Email, "Confirm your mail", body);

        return await _emailService.SendEmailAsync(emailSend);
    }

    private async Task<bool> SendForgotUsernameOrPasswordEmail(User user)
    {
        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

        var url = $"{_config["JWT:ClientUrl"]}/{_config["Email:ResetPasswordPath"]}?token={token}&email={user.Email}";

        var body = $"<p> hello: {user.FirstName} {user.LastName}" +
                $"<p>Username: {user.UserName}</p>" +
                "<p>In order to reset your password, please click on the following link.<p>" +
                $"<p><a href=\"{url}\">Click here</a>" +
                "<p>Thank you,</p>" +
                $"<br>{_config["Email:ApplicationName"]}";

        var emailSend = new EmailSendDto(user.Email, "forgot your username or password", body);

        return await _emailService.SendEmailAsync(emailSend);
    }
}
