using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using SecurityWebApp.Data;
using SecurityWebApp.Dtos;
using SecurityWebApp.Models;
using SecurityWebApp.Services;
using System;
using System.Linq;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
});

builder.Services.AddScoped<JWTService>();
builder.Services.AddScoped<EmailService>();
builder.Services.AddScoped<ContextSeedService>();

builder.Services.AddIdentityCore<User>(options =>
{
    options.Password.RequiredLength = 6;
    options.Password.RequireDigit = false;
    options.Password.RequireLowercase = false;
    options.Password.RequireUppercase = false;
    options.Password.RequireNonAlphanumeric = false;

    options.SignIn.RequireConfirmedEmail = true;
})
    .AddRoles<IdentityRole>()
    .AddRoleManager<RoleManager<IdentityRole>>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddSignInManager<SignInManager<User>>()
    .AddUserManager<UserManager<User>>()
    .AddDefaultTokenProviders();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters()
        {
             ValidateIssuerSigningKey = true,
             IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JWT:Key"])),
             ValidateIssuer = true,
             ValidIssuer = builder.Configuration["JWT:Issuer"],
             ValidateAudience = false
        };
    });

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
// builder.Services.AddCors();
builder.Services.AddCors(options =>
{
    options.AddPolicy("CorsPolicy",
        builder => builder.AllowAnyOrigin()
            .AllowAnyMethod()
            .AllowAnyHeader());
});
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("admin", rolePolicy => rolePolicy.RequireRole("admin"));
    options.AddPolicy("manager", rolePolicy => rolePolicy.RequireRole("manager"));
    options.AddPolicy("player", rolePolicy => rolePolicy.RequireRole("player"));
    options.AddPolicy("admin-or-player", rolePolicy => rolePolicy.RequireRole("admin", "player"));
    options.AddPolicy("admin-or-manager", rolePolicy => rolePolicy.RequireRole("admin", "manager"));

    options.AddPolicy("admin-email-policy", claimPolicy => claimPolicy.RequireClaim(ClaimTypes.Email, "admin@gmail.com"));
    options.AddPolicy("ullah-surname-policy", claimPolicy => claimPolicy.RequireClaim(ClaimTypes.Surname, "Ullah"));
    options.AddPolicy("VIPPolicy", policy => policy.RequireAssertion(context => SD.VIPPolicy(context)));
});
builder.Services.Configure<ApiBehaviorOptions>(options =>
{
    options.InvalidModelStateResponseFactory = actionContext =>
    {
        var errors = actionContext.ModelState
        .Where(x => x.Value.Errors.Count > 0)
            .SelectMany(x => x.Value.Errors)
            .Select(x => x.ErrorMessage).ToArray();

        var toReturn = new
        {
            Errors = errors
        };
        return new BadRequestObjectResult(toReturn);
    };
});

var app = builder.Build();
//app.UseCors(c => c.AllowAnyHeader()
//                .AllowAnyMethod()
//                .AllowCredentials()
//                .WithOrigins("*"));
app.UseCors("CorsPolicy");
// Configure the HTTP request pipeline.
//if (app.Environment.IsDevelopment())
//{
    app.UseSwagger();
    app.UseSwaggerUI();
//}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

#region context seed
using var scope = app.Services.CreateScope();
try
{
    var contextSeedService = scope.ServiceProvider.GetRequiredService<ContextSeedService>();
    await contextSeedService.InitializeContextAsync();
}
catch(Exception ex)
{
    var _logger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();
    _logger.LogError(ex.Message, "Failed to initialize and seed the database");
}
#endregion

app.Run();
