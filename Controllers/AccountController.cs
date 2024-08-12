using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using IdenityTest.Models;

[Route("api/[controller]")]
[ApiController]
public class AccountController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IConfiguration _configuration;

    public AccountController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, IConfiguration configuration)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _configuration = configuration;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterModel model)
    {
        var user = new ApplicationUser
        {
            UserName = model.Email,
            Email = model.Email,
            FirstName = model.FirstName,
            LastName = model.LastName,
            Role = model.Role // Rol bilgisini ekleyin
        };
        var result = await _userManager.CreateAsync(user, model.Password);

        if (result.Succeeded)
        {
            return Ok("User registered successfully");
        }

        return BadRequest(result.Errors);
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginModel model)
    {
        var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, false, false);

        if (result.Succeeded)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            var token = GenerateJwtToken(user);
            return Ok(new { Token = token });
        }

        return Unauthorized();
    }

    [HttpGet("profile")]
    [Authorize(Roles = "Junior, Senior")] // Junior ve Senior rolü olanlar erişebilir
    public async Task<IActionResult> GetProfile()
    {
        var userId = User.Claims.FirstOrDefault(c => c.Type == "id")?.Value;
        if (userId == null)
        {
            return Unauthorized();
        }

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return NotFound("User not found");
        }

        return Ok(new
        {
            user.UserName,
            user.Email,
            user.FirstName,
            user.LastName
        });
    }
    [HttpGet("all")]
    [Authorize(Roles = "Senior")]
    public async Task<IActionResult> GetAllUsers()
    {
        var users = _userManager.Users.ToList(); // Get all users
        var userProfiles = users.Select(user => new
        {
            user.UserName,
            user.Email,
            user.FirstName,
            user.LastName,
            user.Role
        }).ToList();

        return Ok(userProfiles);
    }

    [HttpDelete("delete")]
    [Authorize(Roles = "Senior")] // Sadece Senior rolü olanlar erişebilir
    public async Task<IActionResult> DeleteUser([FromBody] DeleteUserModel model)
    {
        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null)
        {
            return NotFound("User not found");
        }

        var result = await _userManager.DeleteAsync(user);

        if (result.Succeeded)
        {
            return Ok("User deleted successfully");
        }

        return BadRequest(result.Errors);
    }

    private string GenerateJwtToken(ApplicationUser user)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_configuration["Jwt:Key"]);
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim("id", user.Id),
                new Claim(ClaimTypes.Role, user.Role) 
            }),
            Expires = DateTime.UtcNow.AddHours(1),
            Issuer = _configuration["Jwt:Issuer"],
            Audience = _configuration["Jwt:Issuer"],
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }
}
