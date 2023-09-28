using Google.Apis.Auth;
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
using System.Net.Http;
using System.Net.Http.Json;
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
    private readonly HttpClient _facebookHttpClient;

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
        _facebookHttpClient = new HttpClient()
        {
            BaseAddress = new Uri("https://graph.facebook.com")
        };
    }

    [HttpPost("login")]
    public async Task<ActionResult<UserDto>> Login(LoginDto model)
    {
        var user = await _userManager.FindByNameAsync(model.UserName);
        if (user is null) return Unauthorized("invalid username or password");

        if (user.EmailConfirmed == false) return Unauthorized("please confirm your email.");

        var result = await _signInManager.CheckPasswordSignInAsync(user, model.Password, false);

        if (result.IsLockedOut) return Unauthorized(string.Format("your account has been locked. you should wait until {0} (UTC time) to be able to login", user.LockoutEnd));

        if (!result.Succeeded)
        {
            if(!user.UserName.Equals(SD.AdminUserName))
                await _userManager.AccessFailedAsync(user);
            if(user.AccessFailedCount >= SD.MaximumLoginAttempts)
            {
                await _userManager.SetLockoutEndDateAsync(user, DateTime.UtcNow.AddDays(1));
                return Unauthorized(string.Format("your account has been locked. you should wait until {0} (UTC time) to be able to login", user.LockoutEnd));
            }
            return Unauthorized("Invalid username or password.");
        }

        await _userManager.ResetAccessFailedCountAsync(user);
        await _userManager.SetLockoutEndDateAsync(user, null);

        return await CreateApplicationUserDto(user);
    }

    [HttpPost("login-with-third-party")]
    public async Task<ActionResult<UserDto>> LoginWithThirdParty([FromBody] LoginWithExternalDto model)
    {
        if (model.Provider.Equals(SD.Facebook))
        {
            try
            {
                if (!FacebookValidatedAsync(model.AccessToken, model.UserId).GetAwaiter().GetResult())
                {
                    return Unauthorized("login unauthorized");
                }
            }
            catch (Exception ex)
            {
                return Unauthorized();
            }
        }
        else if (model.Provider == SD.Google)
        {
            try
            {
                if (!GoogleValidateAsync(model.AccessToken, model.UserId).GetAwaiter().GetResult())
                    return Unauthorized("Google login failed");
            }
            catch (Exception ex)
            {
                return Unauthorized(string.Format("Google login failed message: {0}", ex.Message));
            }
        }
        else
        {
            return BadRequest("Invalid provider");
        }

        var user = await _userManager.Users.FirstOrDefaultAsync(x => 
        x.UserName == model.UserId && x.Provider == model.Provider
        );
        if (user == null)
            return BadRequest("Unable to find your account");

        return  await CreateApplicationUserDto(user);
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
        await _userManager.AddToRoleAsync(userToAdd, SD.Player);

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

    [HttpPost("register-with-third-party")]
    public async Task<ActionResult<UserDto>> RegisterWithThirdParty([FromBody] RegisterWithExternalDto model)
    {
        if(model.Provider.Equals(SD.Facebook))
        {
            try
            {
                if(!FacebookValidatedAsync(model.AccessToken, model.UserId).GetAwaiter().GetResult())
                {
                    return Unauthorized();
                }
            }
            catch (Exception ex)
            {
                return Unauthorized();
            }
        } 
        else if(model.Provider == SD.Google)
        {
            try
            {
                if(!GoogleValidateAsync(model.AccessToken, model.UserId).GetAwaiter().GetResult())
                    return Unauthorized("Google registration failed");
            }
            catch(Exception ex)
            {
                return Unauthorized(string.Format("Google registration failed message: {0}", ex.Message));
            }
        }
        else
        {
            return BadRequest("Invalid provider");
        }

        var user = await _userManager.FindByNameAsync(model.UserId);
        if (user != null) 
            return BadRequest(string.Format("You have an account already. please login with your {0}", model.Provider));

        var userToAdd = new User
        {
            FirstName = model.FirstName.ToLower(),
            LastName = model.LastName.ToLower(),
            UserName = model.UserId,
            Provider = model.Provider
        };
        var result = await _userManager.CreateAsync(userToAdd);

        if (!result.Succeeded) return BadRequest(result.Errors);
        await _userManager.AddToRoleAsync(userToAdd, SD.Player);

        return await CreateApplicationUserDto(userToAdd);
    }
    [Authorize]
    [HttpGet("refresh-user-token")]
    public async Task<ActionResult<UserDto>> RefreshUserToken()
    {
        var user = await _userManager.FindByNameAsync(User.FindFirst(ClaimTypes.Email)?.Value);
        if(await _userManager.IsLockedOutAsync(user))
        {
            return Unauthorized("You have been locked out.");
        }
        return await CreateApplicationUserDto(user);
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
    private async Task<UserDto> CreateApplicationUserDto(User user)
    {
        return new UserDto
        {
            FirstName = user.FirstName,
            LastName = user.LastName,
            JWT = await _jWTService.CreateJWT(user)
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

    private async Task<bool> FacebookValidatedAsync(string accessToken, string userId)
    {
        var facebook = $"{_config["Facebook:AppId"]}|{_config["Facebook:AppSecret"]}";
        var fbResult = await _facebookHttpClient.GetFromJsonAsync<FacebookResultDto>($"debug_token?input_token={accessToken}&access_token={facebook}");
        if(fbResult.Data.IsValid=false && fbResult is null && !fbResult.Data.UserId.Equals(userId))
            return false;
        return true;
    }

    private async Task<bool> GoogleValidateAsync(string accessToken, string userId)
    {
        var payload = await GoogleJsonWebSignature.ValidateAsync(accessToken);

        if (!payload.Audience.Equals(_config["Google:ClientId"]))
            return false;

        if(!payload.Issuer.Equals("accounts.google.com") && !payload.Issuer.Equals("https://accounts.google.com"))
            return false;

        if (payload.ExpirationTimeSeconds == null)
            return false;

        DateTime now = DateTime.Now.ToUniversalTime();
        DateTime expiration = DateTimeOffset.FromUnixTimeSeconds((long)payload.ExpirationTimeSeconds).DateTime;
        if(now > expiration) 
            return false;

        if(!payload.Subject.Equals(userId))
            return false;

        return true;
    }
}
