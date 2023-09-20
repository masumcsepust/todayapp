using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SecurityWebApp.Dtos;
using SecurityWebApp.Dtos.Admin;
using SecurityWebApp.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SecurityWebApp.Controllers;

[Route("api/[controller]")]
[ApiController]
[Authorize]
public class AdminController : ControllerBase
{
    private readonly UserManager<User> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;

    public AdminController(UserManager<User> userManager, RoleManager<IdentityRole> roleManager)
    {
        _userManager = userManager;
        _roleManager = roleManager;
    }

    [HttpGet("get-members")]
    public async Task<ActionResult<IEnumerable<MemberViewDto>>> GetMembers()
    {
        var members = await _userManager.Users
            .Where(x => x.UserName != "admin@gmail.com")
            .Select(member => new MemberViewDto
            {
                Id = member.Id,
                FirstName = member.FirstName,
                LastName = member.LastName,
                DateCreated = member.DateCreated,
                IsLoacked = _userManager.IsLockedOutAsync(member).GetAwaiter().GetResult(),
                Roles = _userManager.GetRolesAsync(member).GetAwaiter().GetResult()
            }).ToListAsync();

        return Ok(members);
    }

    [HttpPut("lock-member/{id}")]
    public async Task<IActionResult> LockMember(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null) return NoContent();

        if (IsAdminUserId(user.Id))
            return BadRequest("super admin does not allow to modified");
        await _userManager.SetLockoutEndDateAsync(user, DateTime.UtcNow.AddDays(1));
        return NoContent();
    }

    [HttpPut("unlock-member/{id}")]
    public async Task<IActionResult> UnlockMember(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null) return NoContent();

        if (IsAdminUserId(user.Id))
            return BadRequest("super admin does not allow to modified");
        await _userManager.SetLockoutEndDateAsync(user, null);
        return NoContent();
    }

    [HttpDelete("Delete/{id}")]
    public async Task<IActionResult> DeleteMember(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null) return NoContent();

        if (IsAdminUserId(user.Id))
            return BadRequest("super admin does not allow to modified");

        await _userManager.DeleteAsync(user);
        return NoContent();
    }

    [HttpGet("get-application-roles")]
    public async Task<ActionResult<List<string>>> GetRoles()
    {
        return await _roleManager.Roles.Select(x => x.Name).ToListAsync();
    }

    [HttpGet("get-member/{id}")]
    public async Task<ActionResult<MemberAddEditDto>> GetMember(string id)
    {
        var member = await _userManager.Users
            .Where(x => x.UserName != SD.AdminUserName && x.Id == id)
            .Select(m => new MemberAddEditDto { 
                 Id = m.Id,
                 FirstName= m.FirstName,
                 LastName= m.LastName,
                 UserName= m.UserName,
                 Roles = string.Join(",", _userManager.GetRolesAsync(m).GetAwaiter().GetResult())
            })
            .FirstOrDefaultAsync();
        return Ok(member);
    }

    [HttpPost("add-edit-member")]
    public async Task<IActionResult> AddEditMember([FromBody] MemberAddEditDto model)
    {
        User user;
        if(string.IsNullOrEmpty(model.Id)) 
        {
            if (string.IsNullOrEmpty(model.Password) || model.Password.Length > 6)
            {
                ModelState.AddModelError("errors", "Password must be at least 6 characters.");
                return BadRequest(ModelState);
            }

            user = new User
            {
                FirstName = model.FirstName.ToLower(),
                LastName = model.LastName.ToLower(),
                UserName = model.UserName.ToLower(),
                EmailConfirmed = true
            };

            var result = await _userManager.CreateAsync(user, model.Password);
            if(!result.Succeeded) return BadRequest(result.Errors);
        }
        else
        {
            if (!string.IsNullOrEmpty(model.Password))
            {
                if (model.Password.Length < 6)
                {
                    ModelState.AddModelError("errors", "Password must be at least 6 characters");
                    return BadRequest(ModelState);
                }
            }

                if(IsAdminUserId(model.Id))
                {
                    return BadRequest("Super does not allow to change.");
                }

            user = await _userManager.FindByIdAsync(model.Id);
            if (user == null) return NotFound();

            user.FirstName = model.FirstName.ToLower();
            user.LastName = model.LastName.ToLower();
            user.UserName = model.UserName.ToLower();

            if(!string.IsNullOrEmpty(model.Password))
            {
                await _userManager.RemovePasswordAsync(user);
                await _userManager.AddPasswordAsync(user, model.Password);
            }

            if (string.IsNullOrEmpty(model.Id))
                return Ok(new JsonResult(new { Title = "Member Created", Message = $"{model.UserName} has been created." }));
            else
                return Ok(new JsonResult(new { Title = "Member edited", Message = $"{model.UserName} has been updated." }));
        }

        var userRoles = await _userManager.GetRolesAsync(user);

        // removing users existing role(s)
        await _userManager.RemoveFromRolesAsync(user, userRoles);

        foreach(var role in model.Roles.Split(",").ToArray())
        {
            var roleToAdd = await _roleManager.Roles.FirstOrDefaultAsync(r => r.Name == role);
            if(roleToAdd != null)
            {
                await _userManager.AddToRoleAsync(user, role);
            }
        }

        return Ok();
    }
    private bool IsAdminUserId(string userId)
    {
        return _userManager
            .FindByIdAsync(userId).GetAwaiter().GetResult()
            .UserName
            .Equals(SD.AdminUserName);
    }
}
