using System.Security.Cryptography;
using System.Text;
using API.Data;
using API.DTOs;
using API.Entities;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AccountController : BaseAPIController
    {
        private readonly DataContext _context;

        public AccountController(DataContext context)
        {
            _context = context;
        }

        [HttpPost(template: "Register")]
        public async Task<ActionResult<AppUser>> Register(RegisterDto dto)
        {
            // Check if user exists
            if (await UserExists(dto.UserName))
                return BadRequest("Username is taken");

            using var hmac = new HMACSHA512();

            var user = new AppUser
            {
                UserName = dto.UserName.ToLower(),
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(dto.Password)),
                PasswordSalt = hmac.Key
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return user;
        }

        [HttpPost("Login")]
        public async Task<ActionResult<AppUser>> Login(LoginDto dto)
        {
            var user = await _context.Users.SingleOrDefaultAsync(
                pred => pred.UserName.ToLower() == dto.UserName.ToLower()
            );

            if (user == null)
                return Unauthorized("Invalid Username.");

            using var hmac = new HMACSHA512(user.PasswordSalt);

            var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(dto.Password));

            for (int i = 0; i < computedHash.Length; i++)
            {
                if (computedHash[i] != user.PasswordHash[i])
                    return Unauthorized("Invalid password.");
            }

            return user;
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
