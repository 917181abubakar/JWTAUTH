using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using TestApi.Data;
using TestApi.Models.AuthModels.DTOs;
using TestApi.Models.DTOs;
using TestApi.Models.UserManager;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Threading.Tasks;
using System;
using Microsoft.AspNetCore.Identity.Data;
using Newtonsoft.Json.Linq;
using System.Security.Cryptography;
using TestApi.Models.AuthModels.Models;
using Azure.Core;
using NuGet.Protocol.Plugins;
using Microsoft.VisualStudio.Web.CodeGenerators.Mvc.Templates.BlazorIdentity.Pages;
using TestApi.Services;
using Azure;
using Microsoft.VisualStudio.Web.CodeGenerators.Mvc.Templates.BlazorIdentity.Pages.Manage;

namespace TestApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IConfiguration _configuration;
        private readonly IEmailSendService _emailsend;

        public AuthController(IConfiguration configuration, ApplicationDbContext context, UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager,IEmailSendService emailsend)
        {
            _context = context;
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
            _emailsend = emailsend;
        }
        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }
        private string GenerateToken(IdentityUser userInfo)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_configuration["Jwt:Key"]);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name, userInfo.UserName),
                    new Claim(ClaimTypes.NameIdentifier, userInfo.Id)
                }),
                TokenType="Bearer",
                Issuer = _configuration["Jwt:Issuer"],
                Audience = _configuration["Jwt:Audience"],
                Expires = DateTime.UtcNow.AddMinutes(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                // var confirmationLink = $"http://localhost:4200/confirm-account?Token={tokenResponse.Response.Token}&email={registerUser.Email}";
                var confirmationLink = Url.Action(nameof(ConfirmEmail), "Auth", new { token, email = user.Email }, Request.Scheme);
                { }
                var res= await _emailsend.SendEmailAsync("Abubkrsdq06@gmail.com", "Confirm Email", $"hell  {confirmationLink}");
                return Ok(new { Message = "User registered and logged in successfully" });
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
            return BadRequest(ModelState);
        }
        [HttpGet("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                var result = await _userManager.ConfirmEmailAsync(user, token);
                if (result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status200OK,
                      new  { Status = "Success", Message = "Email Verified Successfully" });
                }
            }
            return StatusCode(StatusCodes.Status500InternalServerError,
                       new  { Status = "Error", Message = "This User Doesnot exist!" });
        }


        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginDto model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);

            if (user == null)
                return Unauthorized();
            if (user.TwoFactorEnabled)
            {
                //await _signInManager.SignOutAsync();
                await _signInManager.PasswordSignInAsync(user, model.Password, false, true);
                var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");


                await _emailsend.SendEmailAsync("Abubkrsdq06@gmail.com", "OTP Confrimation",token);

                return StatusCode(StatusCodes.Status200OK,
                 new  { Status = "Success", Message = $"We have sent an OTP to your Email {user.Email}" });
            }

            var result = await _signInManager.CheckPasswordSignInAsync(user, model.Password, false);

            if (!result.Succeeded)
                return Unauthorized();

            var tokenString = GenerateToken(user);
            
             var refreshtoken = GenerateRefreshToken();
             user.refreshtoken = refreshtoken;

            _context.SaveChanges();
            return Ok(new { 
                Tokentype="Bearer",
                Token = tokenString,
                expires=DateTimeOffset.UtcNow.AddMinutes(1),
                refreshtoken


            });
        }

        [HttpPost]
        [Route("login-2FA")]
        public async Task<IActionResult> LoginWithOTP(string code, string username)
        {
            var user = await _userManager.FindByNameAsync(username);
            var signIn = await _signInManager.TwoFactorSignInAsync("Email", code, false, false);
            if (signIn.Succeeded)
            {
                if (user != null)
                {

                    var tokenString = GenerateToken(user);

                    var refreshtoken = GenerateRefreshToken();
                    user.refreshtoken = refreshtoken;

                    _context.SaveChanges();
                    return Ok(new
                    {
                        Tokentype = "Bearer",
                        Token = tokenString,
                        expires = DateTimeOffset.UtcNow.AddMinutes(1),
                        refreshtoken


                    });




                }
            }
            return StatusCode(StatusCodes.Status404NotFound,
                new  { Status = "Success", Message = $"Invalid Code" });
        }
        [HttpPost("Refresh")]
        public async Task<IActionResult> Refresh([FromBody] RefreshModel model)
        {
            var principal = validateaccesstoke(model.accesstoken);

            if (principal.Identity.Name == null)
                return Unauthorized();

            var user = await _userManager.FindByNameAsync(principal.Identity.Name);
            if (model.refreshtoken != user.refreshtoken && user.expire_at <= DateTime.Now)
            {
                return Unauthorized(new {
                

                    IsSuccess = false,
                    StatusCode = 400,
                    Message = $"Token invalid or expired"
                });
            }
  

            var tokenString = GenerateToken(user);

            return Ok(new
            {
                Tokentype = "Bearer",
                Token = tokenString,
                expires = DateTimeOffset.UtcNow.AddMinutes(1),
                refreshtoken=model.refreshtoken


            });
        }

        private ClaimsPrincipal? validateaccesstoke(string accesstoken)
        {

            var tokenValidationParameters = new TokenValidationParameters
            {
                //ValidateAudience = false,
                //ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"])),
                //ValidateLifetime = false,

            LogTokenId = false,
            LogValidationExceptions = false,
            RequireExpirationTime = false,
            RequireSignedTokens = false,
            RequireAudience = false,
            SaveSigninToken = false,
            ValidateActor = false,
            ValidateAudience = false,
            ValidateIssuer = false,
            ValidateLifetime = true,
            ValidateTokenReplay = false,
        };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(accesstoken, tokenValidationParameters, out SecurityToken securityToken);

            return principal;
        }
    }
}
