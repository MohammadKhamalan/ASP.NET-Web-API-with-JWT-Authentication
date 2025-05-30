using JwtAuthApi.Helpers;
using JwtAuthApi.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JwtAuthApi.Controllers
{

    [ApiController]
    [Route("api/[controller]")]
    public class AuthController: ControllerBase
    {
        private readonly JwtTokenGenerator _tokenGenerator;

        public AuthController(JwtTokenGenerator tokenGenerator)
        {
            _tokenGenerator = tokenGenerator;
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginRequest request)
        {
            if(request.Username=="mohammad" && request.Password == "12345")
            {
                var token = _tokenGenerator.GenerateToken(request.Username);
                return Ok(new { Token = token });
            }
            return Unauthorized("Invalid credentials");
        }

        [HttpPost("validate")]
        public IActionResult Validate([FromBody] string token)
        {
            var principal = _tokenGenerator.ValidateToken(token);
            if (principal == null)
                return Unauthorized("Token is invalid or expired.");

            return Ok($"Token is valid. Hello, {principal.Identity?.Name}!");
        }

        [Authorize]
        [HttpGet("welcome")]
        public IActionResult welcome()
        {
            return Ok($"Welcome, {User.Identity?.Name}! Today’s weather is sunny.");

        }
    }
}
