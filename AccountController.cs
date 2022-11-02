namespace LogAndReadBackEnd.Controllers
{
    using System;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading.Tasks;
    using LogAndReadBackEnd.Data;
    using LogAndReadBackEnd.DTOs;
    using LogAndReadBackEnd.Entities;
    using LogAndReadBackEnd.Services;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.EntityFrameworkCore;

    public class AccountController : BaseController
    {
        private readonly DataContext context;
        private readonly ITokenService tokenService;

        public AccountController(DataContext context, ITokenService tokenService)
        {
            context = context;
            tokenService = tokenService;
        }

        [HttpPost("/register")]
        public async Task<ActionResult<UserDto>> register([FromBody]RegisterDto registerDto)
        {
            if (await userExists(registerDto.Username))
            {
                return BadRequest("Username is Taken");
            }

            using var hmac = new HMACSHA512();
        
            var user = new WebUser
            {
                Username = registerDto.Username.ToLower(),
                Password = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
                PasswordSalt = hmac.Key,
                CreationTime = DateTime.Now
            };
            context.Users.Add(user);
            await context.SaveChangesAsync();
        
            return new UserDto
            {
                Username = registerDto.Username,
                Token = tokenService.CreateToken(user)
            };
        }

        [HttpPost("login")]
        public async Task<ActionResult<UserDto>> logIn([FromBody] LoginDto loginDto)
        {
            var u = await context.Users.SingleOrDefaultAsync(user => user.Username == loginDto.Username);
            if (u == null)
            { return Unauthorized("Invalid username");
            }

            using var hmac = new HMACSHA512(u.Password);
            var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));
            if (!computedHash.SequenceEqual(u.Password))
            {
                return Unauthorized("Invalid password");

            }

            return new UserDto
            {
                Id = u.Id,
                Username = u.Username,
                Token = tokenService.CreateToken(u)
            };
        }

        private Task<bool> userExists(string username)
        {
            return context.Users.AnyAsync(user => user.Username == username);
        }
    }
}
