using System;
using System.Collections.Generic;

namespace SecurityWebApp.Dtos.Admin;
public class MemberViewDto
{
    public string Id { get; set; }
    public string UserName { get; set; }
    public string FirstName { get; set; }
    public string LastName { get; set; }
    public bool IsLoacked { get; set; }
    public DateTime DateCreated { get; set; }
    public IEnumerable<string> Roles { get; set; }
}
