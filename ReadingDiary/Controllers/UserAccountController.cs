using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using System.Web.Http.Cors;
using ReadingDiary.Models;
using System.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Security.Cryptography;
using System.Security.Claims;
using System.Web.Http.Description;
using System.Text;

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
                //user.Password = HashFunction(user.Password);
                //byte[] passwordHash, passwordSalt;
                //user.Password = CreatePasswordHash(user.Password, out passwordHash, out passwordSalt);
                string key = "4521";
                user.Password = GenerateHMac(key, user.Password);
                db.Users.Add(user);
                db.SaveChanges();
                return CreatedAtRoute("DefaultApi", new { id = user.Id }, user);
            }            
        }

        private string HashFunction(string pass)
        {
            byte[] salt;
            new RNGCryptoServiceProvider().GetBytes(salt = new byte[16]);
            var pbkdf2 = new Rfc2898DeriveBytes(pass, salt, 1000);
            byte[] hash = pbkdf2.GetBytes(20);
            byte[] hashBytes = new byte[36];
            Array.Copy(salt, 0, hashBytes, 0, 16);
            Array.Copy(hash, 0, hashBytes, 16, 20);
            return Convert.ToBase64String(hashBytes);
        }

        private string CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new System.Security.Cryptography.HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));                
            }
            return Convert.ToBase64String(passwordHash);
        }

        [HttpPost, AllowAnonymous, Route("api/useraccount/login")]
        public IHttpActionResult Authenticate([FromBody] LoginRequest login)
        {
            var loginResponse = new LoginResponse { };
            //LoginRequest loginrequest = new LoginRequest { };
            //loginrequest.Username = login.Username.ToLower();
            //loginrequest.Password = login.Password;

            IHttpActionResult response;
            HttpResponseMessage responseMsg = new HttpResponseMessage();
            //bool isUsernamePasswordValid = false;

            //Check credentials
            if (login != null)
            {
                //isUsernamePasswordValid = loginrequest.Password == "admin" ? true : false;
                //User user = db.Users.Find(login.Username);
                User user = db.Users.FirstOrDefault(x => x.Username == login.Username);
                //byte[] passwordHash, passwordSalt;
                //string pass = CreatePasswordHash(login.Password, out passwordHash, out passwordSalt);
                //string pass = this.HashFunction(login.Password);
                string key = "4521";
                string pass = GenerateHMac(key, login.Password);
                if (user!=null && pass.Equals(user.Password))
                {
                    string token = createToken(login.Username);
                    //return the token
                    return Ok<string>(token);
                }
                if (user == null)
                {
                    return NotFound();
                }
                else
                {
                    // if credentials are not valid send unauthorized status code in response
                    loginResponse.responseMsg.StatusCode = HttpStatusCode.Unauthorized;
                    response = ResponseMessage(loginResponse.responseMsg);
                    return response;
                }
            }
            return NotFound();
        }

        public string GenerateHMac(string key, string message)
        {
            var decodedKey = Convert.FromBase64String(key);
            var hasher = new HMACSHA256(decodedKey);
            var messageBytes = Encoding.Default.GetBytes(message);
            var hash = hasher.ComputeHash(messageBytes);
            return Convert.ToBase64String(hash);
        }

        private string createToken(string username)
        {
            //Set issued at date
            DateTime issuedAt = DateTime.UtcNow;
            //set the time when it expires
            DateTime expires = DateTime.UtcNow.AddDays(7);

            //http://stackoverflow.com/questions/18223868/how-to-encrypt-jwt-security-token
            var tokenHandler = new JwtSecurityTokenHandler();

            //create a identity and add claims to the user which we want to log in
            ClaimsIdentity claimsIdentity = new ClaimsIdentity(new[]
            {
                new Claim(ClaimTypes.Name, username)
            });

            const string sec = "401b09eab3c013d4ca54922bb802bec8fd5318192b0a75f201d8b3727429090fb337591abd3e44453b954555b7a0812e1081c39b740293f765eae731f5a65ed1";
            var now = DateTime.UtcNow;
            var securityKey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(System.Text.Encoding.Default.GetBytes(sec));
            var signingCredentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(securityKey, Microsoft.IdentityModel.Tokens.SecurityAlgorithms.HmacSha256Signature);


            //create the jwt
            var token =
                (JwtSecurityToken)
                    tokenHandler.CreateJwtSecurityToken(issuer: "http://localhost:51956", audience: "http://localhost:51956",
                        subject: claimsIdentity, notBefore: issuedAt, expires: expires, signingCredentials: signingCredentials);
            var tokenString = tokenHandler.WriteToken(token);

            return tokenString;
        }

    }
}
