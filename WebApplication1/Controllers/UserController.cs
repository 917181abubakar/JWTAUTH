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
using Microsoft.AspNetCore.Identity.Data;
using TestApi.Models.AuthModels.Models;

namespace TestApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;


        public UserController(ApplicationDbContext context, UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager)
        {
            _context = context;
            _userManager = userManager;
            _signInManager = signInManager;


        }
        

        [Authorize]
        [HttpGet]
        public async Task<ActionResult<IEnumerable<EmpUserDto>>> Getusers()
        {
            var users = await _context.emp_users
                .Include(u => u.User_Groups)
                .ThenInclude(ug => ug.user_Groups)
                .ToListAsync();

            var userdtos = users.Select(
                u => new EmpUserDto
                {
                    Employeeid = u.Employeeid,
                    Email = u.Email,
                    firstname = u.firstname,
                    lastname = u.lastname,
                    User_Groupsdto = u.User_Groups.Select(g => new GroupsDto
                    {
                        Groupid = g.GroupId,
                        GroupName = g.user_Groups?.GroupName

                    }).ToList(),
                }
                ).ToList();
            return Ok(userdtos);

        }
        [HttpGet("{id}")]
        public async Task<ActionResult<IEnumerable<EmpUserDto>>> Getusers(int id)
        {
            var users = await _context.emp_users
                .Include(u => u.User_Groups)
                .ThenInclude(ug => ug.user_Groups)
                .FirstOrDefaultAsync(u => u.Employeeid == id);

            if (users == null)
            {
                return NotFound();
            }

            var userdtos = new EmpUserDto
            {
                Employeeid = users.Employeeid,
                Email = users.Email,
                firstname = users.firstname,
                lastname = users.lastname,
                User_Groupsdto = users.User_Groups.Select(g => new GroupsDto
                {
                    Groupid = g.GroupId,
                    GroupName = g.user_Groups.GroupName

                }).ToList()
            };
            return Ok(userdtos);

        }

        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteUser(int id)
        {
            var user = await _context.emp_users
                .Include(u => u.User_Groups) // Include related user groups for deletion
                .FirstOrDefaultAsync(u => u.Employeeid == id);

            if (user == null)
            {
                return NotFound();
            }

            // Remove user group associations first (optional for cascading deletes)
            if (user.User_Groups != null)
            {
                _context.RemoveRange(user.User_Groups); // Remove all associated groups
            }

            // Remove the user from the database
            _context.emp_users.Remove(user);
            await _context.SaveChangesAsync();

            return NoContent(); // Indicate successful deletion without content
        }

       
           
        [HttpPost]
        public async Task<IActionResult> CreateUser([FromBody] EmpUserDto userDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState); // Return validation errors
            }
            var userGroups = new List<UserGroups>();

            if (userDto.User_Groupsdto != null)
            {
                foreach (var groupDto in userDto.User_Groupsdto)
                {
                    var groupId = _context.Groups
                                          .Where(g => g.GroupName.ToLower() == groupDto.GroupName.ToLower())
                                          .Select(g => g.Groupid)
                                          .FirstOrDefault();

                    if (groupId == 0)
                    {
                        return BadRequest($"Group '{groupDto.GroupName}' does not exist.");
                    }

                    userGroups.Add(new UserGroups
                    {
                        GroupId = groupId
                    });
                }
            }

            var user = new EmployeeUsers
            {
                Email = userDto.Email,
                firstname = userDto.firstname,
                lastname = userDto.lastname,
                User_Groups = userGroups
            };

            _context.emp_users.Add(user);
            await _context.SaveChangesAsync();

            return Ok(user);

        }

    }

}
