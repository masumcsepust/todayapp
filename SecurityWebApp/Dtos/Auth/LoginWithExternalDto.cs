using System.ComponentModel.DataAnnotations;

namespace SecurityWebApp.Dtos.Auth;

public record LoginWithExternalDto(
     string Provider,
     string AccessToken,
     string UserId);
