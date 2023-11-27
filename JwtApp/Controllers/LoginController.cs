using JwtApp.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Mail;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;


namespace JwtApp.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private IConfiguration _config;

        public LoginController(IConfiguration config)
        {
            _config = config;
        }

        [AllowAnonymous]
        [HttpPost]
        public IActionResult Login([FromBody] UserLogin userLogin)
        {
            try
            {
                if (!IsValidEmail(userLogin.EmailAddress))
                {
                    return BadRequest("Invalid email address");
                }

                var user = Authenticate(userLogin);

                if (user != null && user.IsEmailVerified)
                {
                    var token = Generate(user);
                    return Ok(token);
                }

                return NotFound("User,Password or Email not found ");
            }
            catch (Exception ex)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, $"Internal server error: {ex.Message}");
            }
        }

        private bool IsValidEmail(string email)
        {
            try
            {
                var mailAddress = new MailAddress(email);
                return true;
            }
            catch
            {
                return false;   
            }
        }
        private string Generate(UserModel user)
        {
            try
            {
                var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
                var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

                var claims = new[]
                {
                    new Claim(ClaimTypes.NameIdentifier, user.Username),
                    new Claim(ClaimTypes.Email, user.EmailAddress),
                    new Claim(ClaimTypes.GivenName, user.GivenName),
                    new Claim(ClaimTypes.Surname, user.Surname),
                    new Claim(ClaimTypes.Role, user.Role)
                };

                var token = new JwtSecurityToken(_config["Jwt:Issuer"],
                    _config["Jwt:Audience"],
                    claims,
                    expires: DateTime.Now.AddMinutes(15),
                    signingCredentials: credentials);

                return new JwtSecurityTokenHandler().WriteToken(token);

            }
            catch (Exception ex)
            {
                throw new ApplicationException("Error generating JWT", ex);
            }
        }
        private UserModel Authenticate(UserLogin userLogin)
        {
            try
            {
                var currentUser = UserConstants.Users.FirstOrDefault(o =>
                   o.Username.ToLower() == userLogin.Username.ToLower() &&
                   o.Password == userLogin.Password &&
                   o.IsEmailVerified && string.Equals(o.EmailAddress, userLogin.EmailAddress, StringComparison.OrdinalIgnoreCase));

                return currentUser;
            }


            catch (Exception ex)
            {
                throw new ApplicationException("Error authenticating user", ex);
            }
        }
    } 
}