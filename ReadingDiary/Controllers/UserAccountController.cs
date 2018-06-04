using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using System.Web.Http.Cors;
using ReadingDiary.Models;
using System.Security.Cryptography;
using System.Web.Http.Description;

namespace ReadingDiary.Controllers
{
    //[RoutePrefix("api/users")]
    [EnableCors(origins: "http://localhost:4200", headers: "*", methods: "*")]
    public class UserAccountController : ApiController
    {
        private ReadingDiaryEntities db = new ReadingDiaryEntities();
 
        [ResponseType(typeof(User))]
        [HttpPost]
        public IHttpActionResult Register(User user)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            else if (db.Users.Any(u => u.Email == user.Email))
            {
                ModelState.AddModelError("Email", "Email already registered.");
                return BadRequest(ModelState);
            }
            else
            {
                user.Password = HashFunction(user.Password);
                db.Users.Add(user);
                db.SaveChanges();
                return CreatedAtRoute("DefaultApi", new { id = user.Id }, user);
            }            
        }

        private string HashFunction(string pass)
        {
            byte[] salt;
            new RNGCryptoServiceProvider().GetBytes(salt = new byte[16]);
            var pbkdf2 = new Rfc2898DeriveBytes(pass, salt, 10000);
            byte[] hash = pbkdf2.GetBytes(20);
            byte[] hashBytes = new byte[36];
            Array.Copy(salt, 0, hashBytes, 0, 16);
            Array.Copy(hash, 0, hashBytes, 16, 20);
            return Convert.ToBase64String(hashBytes);
        }

        private int EmailExists(string email)
        {
            //db.Users.
            return 0;
        }
    }
}
