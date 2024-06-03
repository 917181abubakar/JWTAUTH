using Microsoft.AspNetCore.Identity;
using Microsoft.Identity.Client;

namespace TestApi.Models.AuthModels.Models
{
    public class ApplicationUser:IdentityUser
    {
        public string refreshtoken { get; set; }
       public DateTime expire_at { get; set; }

    }
}
