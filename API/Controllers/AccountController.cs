using System.Security.Cryptography;
using System.Text;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AccountController : BaseAPIController
    {
        private readonly DataContext _context;
        private readonly ITokenService _tokenService;

        public AccountController(DataContext context, ITokenService tokenService)
        {
            _context = context;
            _tokenService = tokenService;
        }

        [HttpPost(template: "Register")]
        public async Task<ActionResult<UserDto>> Register(RegisterDto dto)
        {
            // Check if user exists
            if (await UserExists(userName: dto.UserName))
                return BadRequest(error: "Username is taken");

            using var hmac = new HMACSHA512();

            var user = new AppUser
            {
                UserName = dto.UserName.ToLower(),
                PasswordHash = hmac.ComputeHash(buffer: Encoding.UTF8.GetBytes(dto.Password)),
                PasswordSalt = hmac.Key
            };

            _context.Users.Add(entity: user);
            await _context.SaveChangesAsync();

            return new UserDto
            {
                UserName = user.UserName,
                Token = _tokenService.CreateToken(user: user)
            };
        }

        [HttpPost("Login")]
        public async Task<ActionResult<UserDto>> Login(LoginDto dto)
        {
            var user = await _context.Users.SingleOrDefaultAsync(
                predicate: pred => pred.UserName.ToLower() == dto.UserName.ToLower()
            );

            if (user == null)
                return Unauthorized(value: "Invalid Username.");

            using var hmac = new HMACSHA512(key: user.PasswordSalt);

            var computedHash = hmac.ComputeHash(buffer: Encoding.UTF8.GetBytes(dto.Password));

            for (int i = 0; i < computedHash.Length; i++)
            {
                if (computedHash[i] != user.PasswordHash[i])
                    return Unauthorized(value: "Invalid password.");
            }

            return new UserDto
            {
                UserName = user.UserName,
                Token = _tokenService.CreateToken(user: user)
            };
        }

        #region Helpers
        /// <summary>
        /// Checks if userName already exists in the DB.
        /// </summary>
        /// <param name="userName">The userName to be checked.</param>
        /// <returns>True: userName already exists in DB.<br/>
        /// False: userName doesn't exist in DB.</returns>
        private async Task<bool> UserExists(string userName)
        {
            return await _context.Users.AnyAsync(
                predicate: pred => pred.UserName == userName.ToLower()
            );
        }
        #endregion
    }
}
