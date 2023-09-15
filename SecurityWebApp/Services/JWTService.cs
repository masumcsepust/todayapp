using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using SecurityWebApp.Models;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace SecurityWebApp.Services;
public class JWTService
{
    private readonly IConfiguration _config;
    private readonly SymmetricSecurityKey _jwtKey;

    public JWTService(IConfiguration config)
	{
        _config = config;
        _jwtKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JWT:Key"]));
    }

    public string CreateJWT(User user)
    {
        var claims = new List<Claim> 
        { 
            new Claim(ClaimTypes.NameIdentifier, user.Id),
            new Claim(ClaimTypes.Email, user.UserName ?? ""),
            new Claim(ClaimTypes.GivenName, user.FirstName),
            new Claim(ClaimTypes.Surname, user.LastName),
            new Claim("my own claim name", "this is the value")
        };

        var credentials = new SigningCredentials(_jwtKey, SecurityAlgorithms.HmacSha256Signature);

        var tokenDescriptor = new SecurityTokenDescriptor()
        {
            Subject = new ClaimsIdentity(claims),
            SigningCredentials = credentials,
            Expires = DateTime.UtcNow.AddDays(int.Parse(_config["JWT:ExpiresInDays"])),
            Issuer = _config["JWT:Issuer"]
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var jwt = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(jwt);
    }
}
