namespace LogAndReadBackEnd.Controllers
{
    using System;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading.Tasks;
    using Data;
    using DTOs;
    using Entities;
    using Services;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.EntityFrameworkCore;

    public class AccountController : BaseController
    {
        private readonly DataContext _context;
        private readonly ITokenService _tokenService;

        public AccountController(DataContext context, ITokenService tokenService)
        {
            this._context = context;
            this._tokenService = tokenService;
        }

        [HttpPost("/register")]
        public async Task<ActionResult<UserDto>> Register([FromBody]RegisterDto registerDto)
        {
            if (await UserExists(registerDto.Username))
            {
                return BadRequest("Username is Taken");
            }

            var user = CreateWebUser(registerDto);
            _context.Users.Add(user);
            await _context.SaveChangesAsync();
        
            return new UserDto
            {
                Username = registerDto.Username,
                Token = _tokenService.CreateToken(user)
            };
        }

        private static WebUser CreateWebUser(RegisterDto registerDto)
        {
            using var hmac = new HMACSHA512();

            var user = new WebUser
            {
                Username = registerDto.Username.ToLower(),
                Password = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
                PasswordSalt = hmac.Key,
                CreationTime = DateTime.Now
            };
            return user;
        }

        [HttpPost("login")]
        public async Task<ActionResult<UserDto>> LogIn([FromBody] LoginDto loginDto)
        {
            var user = await _context.Users.SingleOrDefaultAsync(user => user.Username == loginDto.Username);
            if (user == null)
            { 
                return Unauthorized("Invalid username");
            }

            using var hmac = new HMACSHA512(user.PasswordSalt);
            var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));
            if (!computedHash.SequenceEqual(user.Password))
            {
                return Unauthorized("Invalid password");

            }

            return new UserDto
            {
                Id = user.Id,
                Username = user.Username,
                Token = _tokenService.CreateToken(user)
            };
        }

        private Task<bool> UserExists(string username)
        {
            return _context.Users.AnyAsync(user => user.Username == username);
        }
    }
}
