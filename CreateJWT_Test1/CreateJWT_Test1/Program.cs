using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Newtonsoft.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using System.Text.Json;
using Newtonsoft.Json.Linq;
using System.Windows.Forms;
using System.Globalization;

namespace CreateJWT_Test1
{
    public class Variance
    {
        public string PropertyName { get; set; }
        public List<Variance> Children { get; set; }
        private bool IsValid(string token, double remainingSeconds, out JObject j)
        {
            j = null;
            JwtSecurityToken jwtSecurityToken;
            try
            {
                jwtSecurityToken = new JwtSecurityToken(token);
            }
            catch (Exception)
            {                
                return false;
            }

            j = new JObject(
                new JProperty("HEADER", Newtonsoft.Json.Linq.JObject.FromObject(jwtSecurityToken.Header)),
                new JProperty("PAYLOAD", Newtonsoft.Json.Linq.JObject.FromObject(jwtSecurityToken.Payload))
                );

            return jwtSecurityToken.ValidTo > DateTime.UtcNow.AddSeconds(remainingSeconds);
        }

        public void Test1()
        {
            
            var handler = new JsonWebTokenHandler();
            var now = DateTime.UtcNow;
            string pem = File.ReadAllText(@"C:\Users\User.DESKTOP-GT87VRO\Desktop\Oshry_Iconduct\private.txt"); //private key string;
            PemReader pr = new PemReader(new StringReader(pem));
            AsymmetricCipherKeyPair KeyPair = (AsymmetricCipherKeyPair)pr.ReadObject();
            RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)KeyPair.Private);
            var rsaProvider = RSA.Create(2048); //It'll compatible with .NET Core v2.2
            rsaProvider.ImportParameters(rsaParams);
            var signingKey = new RsaSecurityKey(rsaProvider);
            var signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSsaPssSha256);

            var descriptor = new SecurityTokenDescriptor
            {
                Issuer = "Zodinet Admin",
                Audience = "zodinet",
                IssuedAt = now,
                NotBefore = now,
                Expires = now.AddHours(1),
                Subject = new ClaimsIdentity(new List<Claim> { new Claim("sub", "API Authenticator") }),
                SigningCredentials = signingCredentials
            };
            string token = handler.CreateToken(descriptor);

            Console.ReadLine();

        }

        public void createJWT_Oshry()
        {
            DateTime dateTime = DateTime.UtcNow.AddSeconds((double)int.Parse("1588515464"));
            string JWT_Expires = "1588515464";//JWT_Expires
            string JWT_Algorithm = "PS256";//JWT_Algorithm
            Newtonsoft.Json.Linq.JObject JWT_Header = 
                JsonConvert.DeserializeObject<Newtonsoft.Json.Linq.JObject>
                (
                    File.ReadAllText(@"C:\Users\User.DESKTOP-GT87VRO\Desktop\Oshry_Iconduct\JWT_Header.txt")
                );
            Newtonsoft.Json.Linq.JObject JWT_Payload = 
                JsonConvert.DeserializeObject<Newtonsoft.Json.Linq.JObject>
                (
                    File.ReadAllText(@"C:\Users\User.DESKTOP-GT87VRO\Desktop\Oshry_Iconduct\JWT_Payload.txt")
                );

            string JWT_Header_Claims = "A:1|Key:john";
            if (!string.IsNullOrEmpty(JWT_Header_Claims))
            {
                string str3 = JWT_Header_Claims;
                if (!string.IsNullOrEmpty(str3))
                {
                    string str4 = str3;
                    char[] separator = new char[1] { '|' };
                    foreach (string str5 in str4.Split(separator, StringSplitOptions.RemoveEmptyEntries))
                    {
                        string[] strArray = str5.Split(new char[1]
                        {
                            ':'
                        }, StringSplitOptions.RemoveEmptyEntries);
                        if (strArray.Length == 2)
                            JWT_Header[strArray[0]] = strArray[1];
                    }
                }
            }
            
            string JWT_Payload_Claims = "sub:John Doe|Email:john@mail.com";
            if (!string.IsNullOrEmpty(JWT_Payload_Claims))
            {
                string str3 = JWT_Payload_Claims;
                if (!string.IsNullOrEmpty(str3))
                {
                    string str4 = str3;
                    char[] separator = new char[1] { '|' };
                    foreach (string str5 in str4.Split(separator, StringSplitOptions.RemoveEmptyEntries))
                    {
                        string[] strArray = str5.Split(new char[1]
                        {
                            ':'
                        }, StringSplitOptions.RemoveEmptyEntries);
                        if (strArray.Length == 2)
                            JWT_Payload[strArray[0]] = strArray[1];
                    }
                }
            }


            //---------------- Create JWT
            var handler = new JsonWebTokenHandler();
            var now = DateTime.UtcNow;
            string pem = File.ReadAllText(@"C:\Users\User.DESKTOP-GT87VRO\Desktop\Oshry_Iconduct\private.txt"); //private key string;
            PemReader pr = new PemReader(new StringReader(pem));
            AsymmetricCipherKeyPair KeyPair = (AsymmetricCipherKeyPair)pr.ReadObject();
            RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)KeyPair.Private);
            var rsaProvider = RSA.Create(2048); //It'll compatible with .NET Core v2.2
            rsaProvider.ImportParameters(rsaParams);
            var signingKey = new RsaSecurityKey(rsaProvider);
            var signingCredentials = new SigningCredentials(signingKey, JWT_Algorithm);

            string token = handler.CreateToken(
                //JWT_Payload.ToString(), 
                "{ }",
                signingCredentials, 
                JsonConvert.DeserializeObject<JwtHeader>(JWT_Header.ToString())
                );


            Console.ReadLine();
        }

        public void CreateJWT()
        {
            string str1 = "1588515464";//JWT_Expires
            string str2 = "HS256";//JWT_Algorithm
            string str3 = "sub:0oa3nr4b9bmv60nAe357|iat:1588511863";//JWT_Claims;
            //byte[] numArray = File.ReadAllBytes(@"C:\Users\User.DESKTOP-GT87VRO\Desktop\Oshry_Iconduct\private.txt");//Private key file;
            byte[] numArray = Convert.FromBase64String(File.ReadAllText(@"C:\Users\User.DESKTOP-GT87VRO\Desktop\Oshry_Iconduct\private.txt"));


            DateTime dateTime = DateTime.UtcNow.AddSeconds((double)int.Parse(str1));
            SigningCredentials signingCredentials1 = new SigningCredentials((SecurityKey)new SymmetricSecurityKey(numArray), str2);
            List<Claim> source = new List<Claim>();

            if (!string.IsNullOrEmpty(str3))
            {
                string str4 = str3;
                char[] separator = new char[1] { '|' };
                foreach (string str5 in str4.Split(separator, StringSplitOptions.RemoveEmptyEntries))
                {
                    string[] strArray = str5.Split(new char[1]
                    {
                    ':'
                    }, StringSplitOptions.RemoveEmptyEntries);
                    if (strArray.Length == 2)
                        source.Add(new Claim(strArray[0], strArray[1]));
                }
            }
            
            List<Claim> claimList = source.Any<Claim>() ? source : (List<Claim>)null;
            DateTime? nullable1 = new DateTime?(dateTime);
            SigningCredentials signingCredentials2 = signingCredentials1;
            DateTime? nullable2 = new DateTime?();
            DateTime? nullable3 = nullable1;
            SigningCredentials signingCredentials3 = signingCredentials2;
            JwtSecurityToken jwtSecurityToken = new JwtSecurityToken((string)null, (string)null, (IEnumerable<Claim>)claimList, nullable2, nullable3, signingCredentials3);
            JwtSecurityTokenHandler securityTokenHandler = new JwtSecurityTokenHandler();
            object JWT_Token = (object)((SecurityTokenHandler)securityTokenHandler).WriteToken((SecurityToken)jwtSecurityToken); //JWT_Token
            Console.WriteLine(JWT_Token);
            //return JWT_Token;

        }

        static List<Variance> Recursively(IEnumerable<JProperty> jProperties)
        {
            List<Variance> listOfAll = new List<Variance>();

            foreach (JProperty jProperty in jProperties)
            {
                Variance variance = new Variance
                {
                    PropertyName = jProperty.Path
                };

                if (jProperty.Value.Type == JTokenType.Object)
                {
                    variance.Children = new List<Variance>();
                    List<Variance> recuList = Recursively(((JObject)jProperty.Value).Properties());
                    variance.Children.AddRange(recuList);
                }

                listOfAll.Add(variance);
            }

            return listOfAll;
        }

        static void Switch_keyboard(string lang)
        {
            CultureInfo cultureInfo = CultureInfo.CreateSpecificCulture(lang);
            InputLanguage inputLanguage = InputLanguage.FromCulture(cultureInfo);
            InputLanguage.CurrentInputLanguage = inputLanguage;
        }


        static void Main(string[] args)
        {
            var list = InputLanguage.InstalledInputLanguages.Cast<InputLanguage>().Select(c => c.Culture.Name).ToList();
            Switch_keyboard(list[1]); // "ru-RU" or "ru-BY" ...

            //string js = System.IO.File.ReadAllText(@"C:\Users\User.DESKTOP-GT87VRO\AppData\Local\Google\Chrome\User Data\Default\Preferences");
            //JObject json = JsonConvert.DeserializeObject<JObject>(js);

            //List<Variance> result = Recursively(json.Properties());

            //Variance p = new Variance();
            //string token = @"eyJhbGciOiJSUzI1NiIsImtpZCI6IjQzRjFFNTFDNjc5MDYyQUI5MzJCOEQwQTk0NDAwODNGNEZCMEJCMTciLCJ4NXQiOiJRX0hsSEdlUVlxdVRLNDBLbEVBSVAwLXd1eGMiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2Nsb3VkLnVpcGF0aC5jb20vaWRlbnRpdHlfIiwibmJmIjoxNjk4MDA5MDE2LCJpYXQiOjE2OTgwMDkzMTYsImV4cCI6MTY5ODAxMjkxNiwiYXVkIjoiVWlQYXRoLk9yY2hlc3RyYXRvciIsInNjb3BlIjpbIk9SLkFkbWluaXN0cmF0aW9uIiwiT1IuQW5hbHl0aWNzIiwiT1IuQXNzZXRzIiwiT1IuQXVkaXQiLCJPUi5CYWNrZ3JvdW5kVGFza3MiLCJPUi5FeGVjdXRpb24iLCJPUi5Gb2xkZXJzIiwiT1IuSHlwZXJ2aXNvciIsIk9SLkpvYnMiLCJPUi5NYWNoaW5lcyIsIk9SLk1vbml0b3JpbmciLCJPUi5RdWV1ZXMiLCJPUi5Sb2JvdHMiLCJPUi5TZXR0aW5ncyIsIk9SLlRhc2tzIiwiT1IuVGVzdERhdGFRdWV1ZXMiLCJPUi5UZXN0U2V0RXhlY3V0aW9ucyIsIk9SLlRlc3RTZXRzIiwiT1IuVGVzdFNldFNjaGVkdWxlcyIsIk9SLlVzZXJzIiwiT1IuV2ViaG9va3MiXSwic3ViX3R5cGUiOiJzZXJ2aWNlLmV4dGVybmFsIiwicHJ0X2lkIjoiNzFkYjc5YTEtMGNiYi00NmMyLTkyNzgtOTMxMWVjNTA4NGFiIiwiY2xpZW50X2lkIjoiZGFiOWQ3YjEtOGRiNC00NDA2LWE4MGQtMjM4YmIxZjAzMDkzIiwianRpIjoiNkRBODE3QzA4RDc5Mjc1NDk5QkUzNUNENjQ3MTk4NjUifQ.FLP8cIJCjItM9Mgn5OoTm06SAkZtFobhUgJe7cRKig9E9Md8gI4fgo1S_LkUhV1T0kiUDbJUUfK9CB970ffQ_vJrSZMJkwO9ODIkvAoCoGp8AFP2b6sfOL5ChztyfpymnY2OMeFHIzRoRzr4LBiXMcDfUAjSZbEQ5xiocHrTIEgPKNhGmXPI3thcbms47Db5tXI-wNHB_jfJJP6rgxC5xy4972H79YWWGKI0FhNWTMS7rf85t_TPgHCfu7m4kepVuCJ2-qToSkuKY_TPdlXdnrsTLx0V5c9y5sh1uBSR2OjT37LxEeAYQFSqq5T75pLZQOixvDc55P4-yiM8kYYtPQ";

            ////p.IsValid(token, "20");
            //JObject j;
            //Console.WriteLine(p.IsValid(token, double.Parse("40000"), out j));
            //Console.WriteLine(j.ToString());
            ////p.createJWT_Oshry();
            ////p.Test1();

            Console.ReadLine();

        }
    }
}
