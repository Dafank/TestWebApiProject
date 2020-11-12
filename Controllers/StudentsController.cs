using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using TestWebApi.UserModel;
using TestWebApi.ApiModels;
using Microsoft.AspNetCore.Authorization;
using TestWebApi.Configuration;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Net.WebSockets;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.WebUtilities;

namespace TestWebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Produces("application/json")]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<StudentUser> _userManager;
        private readonly SignInManager<StudentUser> _signInManager;
        private readonly JwtBearerTokenSettings _jwtBearerTokenSettings;

        public AccountController(IOptions<JwtBearerTokenSettings> jwtTokenOptions,UserManager<StudentUser> userManager, SignInManager<StudentUser> signInManager)
        {
            _userManager = userManager;
            _jwtBearerTokenSettings = jwtTokenOptions.Value;
            _signInManager = signInManager;
        }

        [HttpPost("registration")]
        [AllowAnonymous]
        public async Task<IActionResult> Registration([FromBody] RegistrationModel model) 
        {
            

            if (!ModelState.IsValid || model == null) 
            {
                return new BadRequestObjectResult(new { Message = "User Registration Failed" });
            }

            var user = new StudentUser() { Email = model.Email };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded) 
            {
                var dictionary = new ModelStateDictionary();
                foreach (IdentityError error in result.Errors)
                {
                    dictionary.AddModelError(error.Code, error.Description);
                }

                return new BadRequestObjectResult(new { Message = "User Registration Failed", Errors = dictionary });
            }

            return Ok(new { Message = "User Registration Successful" });
        }

        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Loginer([FromBody] LoginModel model) 
        {
            var user = await _userManager.FindByEmailAsync(model.Email);


            if (!ModelState.IsValid || model == null) 
            {
                return new BadRequestObjectResult(new { Message = "Login failed" });
            }

            var result = _userManager.PasswordHasher.VerifyHashedPassword(user, user.PasswordHash, model.Password);

            if (result == PasswordVerificationResult.Failed) 
            {
                return new BadRequestObjectResult(new { Message = "Password is not correct" });
            }
            var token = GenerateToken(user);

            return Ok(new { Token = token, Message = "Success"});
        }

        [HttpPost]
        [Route("logout")]
        public async Task<IActionResult> Logout() 
        {
            return Ok(new { Token = "", Message = "Logged Out" });
        }

        private object GenerateToken(StudentUser user) 
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_jwtBearerTokenSettings.SecretKey);

            var tokenDescription = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Email, user.Email)
                }),

                Expires = DateTime.UtcNow.AddSeconds(_jwtBearerTokenSettings.ExpiryTimeInSeconds),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
                Audience = _jwtBearerTokenSettings.Audience,
                Issuer = _jwtBearerTokenSettings.Issuer
            };

            var token = tokenHandler.CreateToken(tokenDescription);
            return tokenHandler.WriteToken(token);
        }

        [HttpPost("facebookLogin")]
        public async Task<IActionResult> FacebookLogin(string returnUrl) 
        {
            var redirectUrl = Url.Action("FacebookCallBack", "Account",
                            new { ReturnUrl = returnUrl });

            var properties = _signInManager.ConfigureExternalAuthenticationProperties("Facebook", redirectUrl);
            return new ChallengeResult("Facebook", properties);
        }

        [AllowAnonymous]
        public async Task<IActionResult> FacebookCallBack(string returnUrl) 
        {
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null) 
            {
                return new BadRequestObjectResult(new { Message = "External Login Info is null" });
            }

            var email = info.Principal.FindFirst(ClaimTypes.Email);

            if (email != null) 
            {
                var user = await _userManager.FindByEmailAsync(email.Value);

                if (user == null) 
                {
                    user = new StudentUser
                    {
                        Email = info.Principal.FindFirstValue(ClaimTypes.Email)
                    };

                    await _userManager.CreateAsync(user);
                }

                await _userManager.AddLoginAsync(user, info);

                var token = GenerateToken(user);
                return Ok(new { Token = token, Message = "Success" });
            }

            return new BadRequestObjectResult(new { Message = "Email claim not received from Facebook" });

        }
    }
}
