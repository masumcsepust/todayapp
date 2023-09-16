using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SecurityWebApp.Data;
using SecurityWebApp.Dtos;
using SecurityWebApp.Models;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace SecurityWebApp.Services;
public class ContextSeedService
{
    private readonly UserManager<User> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly ApplicationDbContext _dbContext;

    public ContextSeedService(UserManager<User> userManager
		, RoleManager<IdentityRole> roleManager
        , ApplicationDbContext dbContext)
	{
        _userManager = userManager;
        _roleManager = roleManager;
        _dbContext = dbContext;
    }

    public async Task InitializeContextAsync()
    {
        if(_dbContext.Database.GetPendingMigrationsAsync().GetAwaiter().GetResult().Count() > 0)
        {
            await _dbContext.Database.MigrateAsync();
        }
        if(!_roleManager.Roles.Any())
        {
            await _roleManager.CreateAsync(new IdentityRole { Name = SD.Admin});
            await _roleManager.CreateAsync(new IdentityRole { Name = SD.Manager});
            await _roleManager.CreateAsync(new IdentityRole { Name = SD.Player});
        }

        if(!_userManager.Users.AnyAsync().GetAwaiter().GetResult())
        {
            var admin = new User
            {
                FirstName = "Admin",
                LastName = "Billah",
                UserName = "admin@gmail.com",
                Email = "admin@gmail.com",
                EmailConfirmed = true,
            };

            await _userManager.CreateAsync(admin, "123456");
            await _userManager.AddToRolesAsync(admin, new[]
            {
                    SD.Admin
                ,   SD.Manager
                ,   SD.Player
            });
            await _userManager.AddClaimsAsync(admin, new Claim[] {
                new Claim(ClaimTypes.Email, admin.Email),
                new Claim(ClaimTypes.Surname, admin.LastName)
            });

            var manager = new User
            {
                FirstName = "Manager",
                LastName = "Billah",
                UserName = "manager@gmail.com",
                Email = "manager@gmail.com",
                EmailConfirmed = true,
            };

            await _userManager.CreateAsync(manager, "123456");
            await _userManager.AddToRoleAsync(manager,  SD.Manager);
            await _userManager.AddClaimsAsync(manager, new Claim[] {
                new Claim(ClaimTypes.Email, manager.Email),
                new Claim(ClaimTypes.Surname, manager.LastName)
            });

            var player = new User
            {
                FirstName = "Player",
                LastName = "Ullah",
                UserName = "player@gmail.com",
                Email = "player@gmail.com",
                EmailConfirmed = true,
            };

            await _userManager.CreateAsync(player, "123456");
            await _userManager.AddToRoleAsync(player, SD.Player);
            await _userManager.AddClaimsAsync(player, new Claim[] {
                new Claim(ClaimTypes.Email, player.Email),
                new Claim(ClaimTypes.Surname, player.LastName)
            });

            var vipPlayer = new User
            {
                FirstName = "vipPlayer",
                LastName = "Vip",
                UserName = "vipplayer@gmail.com@gmail.com",
                Email = "vipplayer@gmail.com",
                EmailConfirmed = true,
            };

            await _userManager.CreateAsync(vipPlayer, "123456");
            await _userManager.AddToRoleAsync(vipPlayer, SD.Player);
            await _userManager.AddClaimsAsync(vipPlayer, new Claim[] {
                new Claim(ClaimTypes.Email, vipPlayer.Email),
                new Claim(ClaimTypes.Surname, vipPlayer.LastName)
            });
        }
    }
}
