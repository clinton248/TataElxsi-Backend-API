using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using UserManagement.Authentication;

using UserManagement.Models;


namespace UserManagement.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [EnableCors("AllowOrigin")]
    public class AuthenticationController : ControllerBase
    {
        SqlConnection con = new SqlConnection(@"server=104.251.211.189;user id= SA;password=Clintontom1@;database=UserManagementDB");

        private readonly UserManager<ApplicationUser> userManager;
        private readonly IConfiguration _configuration;
        private readonly ApplicationDbContext _context;
        //private readonly FeedBackRepository _FeedBack;
        //private readonly UserDataModel _userData;
        
        public AuthenticationController(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager,IConfiguration configuration, ApplicationDbContext applicationDbContext, IWebHostEnvironment environment, IConfiguration configruation)
        {
            this.userManager = userManager;

            _configuration = configuration;
            _context = applicationDbContext;
       
        }
        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register( [FromBody] RegisterModel model)
        {
            var userexist = await userManager.FindByEmailAsync(model.Email);
            if (userexist != null)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status ="Error",Message="user already exist with this email"});
            var userex = await userManager.FindByNameAsync(model.UserName);
            if(userex != null)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "Use Differnet UserName" });
            ApplicationUser user = new ApplicationUser()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.UserName,
                PhoneNumber=model.PhoneNumber,
                Continent=model.Continent,
                Language=model.Language,
                Country=model.Country,
                Address=model.Address,
            };
          
            var result = await userManager.CreateAsync(user, model.Password); 
            if (!result.Succeeded)
            {
                var errors = new List<String>();
                foreach (var error in result.Errors)
                {
                    errors.Add(error.Description);
                }
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = string.Join(",",errors) });
            };
            return Ok(new Response { Status = "success", Message = "User Created Successsfully" });

        }
        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var user = await userManager.FindByNameAsync(model.UserName);
            if (user != null && await userManager.CheckPasswordAsync(user, model.Password))
            {
                var userRoles = await userManager.GetRolesAsync(user);
                var AuthClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name,user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),

                };
                foreach (var userRole in userRoles)
                {
                    AuthClaims.Add(new Claim(ClaimTypes.Role, userRole));

                }
                var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
                var token = new JwtSecurityToken(
                    issuer: _configuration["JWT:ValidIssuer"],
                    audience: _configuration["JWT:ValidAudience"],
                    expires: DateTime.Now.AddHours(3), 
                    claims: AuthClaims,
                    signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                    );

                return Ok(new { token = new JwtSecurityTokenHandler().WriteToken(token), expiration = token.ValidTo, User = user.UserName });

            }
            return Unauthorized();

        }
        [HttpPost]
        [Route("ResetPassword")]
        //[Authorize]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordModel model)
        {
            var user = await userManager.FindByNameAsync(model.UserName);
            if (user == null)
                return StatusCode(StatusCodes.Status404NotFound, new Response { Status = "error", Message = "User Doesn't Exist" });
            if(string.Compare(model.NewPassword,model.ConfirmNewPassword)!=0)
                return StatusCode(StatusCodes.Status400BadRequest, new Response { Status = "error", Message = "New password and confirm NewPassword doesn't match" });
            var result = await userManager.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword);
            if(!result.Succeeded)
            {
                var errors = new List<String>();
                foreach(var error in result.Errors)
                {
                    errors.Add(error.Description);
                }
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "error", Message = string.Join(",", errors) });

            }
            return Ok(new Response { Status = "Success", Message = "Password successfully Changed !!!" });

        }


        [HttpPut]
        [Route("Edit")]
        public async Task<IActionResult> EditProfile([FromBody] EditProfileModel model)
        {
            var user = await userManager.FindByNameAsync(model.UserName);
            if (user == null)
                return StatusCode(StatusCodes.Status404NotFound, new Response { Status = "error", Message = "User Doesn't Exist" });
            
            SqlCommand cmd = new SqlCommand("UPDATE AspNetUsers SET Username='" + model.UserName + "', PhoneNumber='" + model.PhoneNumber + "', Country='" + model.Country + "', Continent='" + model.Continent + "', Language='" + model.Language + "', Address='" + model.Address + "' WHERE Username='" + user.UserName + "'", con);
            con.Open();
            int i = cmd.ExecuteNonQuery();
            con.Close();
            if (i == 1)
            {
                return Ok(new Response { Status = "Success", Message = "Edited successfully!!!" });
            }
            else
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "error", Message = "Updation Failed" });
            }

        }

        //[Authorize]
        [HttpPost]
        [Route("FeedBack")]
       
        public async Task<ActionResult<FeedBackModel>> PostFeedBacks(FeedBackModel feedBacks)
        {
            _context.FeedBacks.Add(feedBacks);
            await _context.SaveChangesAsync();



            return CreatedAtAction("GetFeedBacks", new { id = feedBacks.Id }, feedBacks);
        }
        public async Task<ActionResult<FeedBackModel>> GetFeedBacks(int id)
        {
            var feedBacks = await _context.FeedBacks.FindAsync(id);

            if (feedBacks == null)
            {
                return NotFound();
            }

            return feedBacks;
        }
        [HttpPost]
        [Route("EmailCheck")]
        //[Authorize]
        public async Task<IActionResult> EmailCheck([FromBody] EmailCheck model)
        {
            var user = await userManager.FindByEmailAsync(model.Email);
            if (user == null)
                return StatusCode(StatusCodes.Status404NotFound, new Response { Status = "error", Message = "User Doesn't Exist" });
            return Ok(new Response { Status = "Success", Message = "Email Exsits" });
        }

        [HttpGet("{name}")]
        [Route("UserData/{name}")]
        [Authorize]

        public async Task<ActionResult<IEnumerable<ApplicationUser>>> GetUser(string name)
        {
            var query = $"SELECT * FROM AspNetUsers WHERE UserName='{name}'";
            var result = await _context.ApplicationUsers.FromSqlRaw(query).ToListAsync<ApplicationUser>();

            if (result.Count == 0)
                return StatusCode(StatusCodes.Status404NotFound, new Response { Status = "error", Message = $"No user registered with name {name}" });
            return result;
        }


    }
}
