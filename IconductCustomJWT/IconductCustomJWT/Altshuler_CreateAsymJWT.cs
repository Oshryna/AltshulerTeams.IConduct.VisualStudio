using IConduct.SDK.v2;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Security.Claims;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Newtonsoft.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using System.Security.Cryptography;

namespace IConduct.Plugins.JWT
{
    //public class IcJwtCreateFromFile : IPlugin
    //{
    //    public PluginResponse Execute(PluginParam param)
    //    {
    //        PluginResponse pluginResponse = new PluginResponse()
    //        {
    //            Messages = new List<PluginMessage>(),
    //            Success = true
    //        };
    //        if (param.Schema == null)
    //            param.Schema = new DataTable();
    //        if (!param.Schema.Columns.Contains("JWT_KeyFilePath"))
    //        {
    //            pluginResponse.Success = false;
    //            pluginResponse.Messages.Add(new PluginMessage()
    //            {
    //                LogLevel = (LogLevel)30,
    //                Message = "'JWT_KeyFilePath' column does not exist in Schema"
    //            });
    //        }
    //        if (!param.Schema.Columns.Contains("JWT_Expires"))
    //        {
    //            pluginResponse.Success = false;
    //            pluginResponse.Messages.Add(new PluginMessage()
    //            {
    //                LogLevel = (LogLevel)30,
    //                Message = "'JWT_Expires' column does not exist in Schema"
    //            });
    //        }
    //        if (!param.Schema.Columns.Contains("JWT_Algorithm"))
    //        {
    //            pluginResponse.Success = false;
    //            pluginResponse.Messages.Add(new PluginMessage()
    //            {
    //                LogLevel = (LogLevel)30,
    //                Message = "'JWT_Algorithm' column does not exist in Schema"
    //            });
    //        }
    //        if (!param.Schema.Columns.Contains("JWT_Token"))
    //        {
    //            pluginResponse.Success = false;
    //            pluginResponse.Messages.Add(new PluginMessage()
    //            {
    //                LogLevel = (LogLevel)30,
    //                Message = "'JWT_Token' column does not exist in Schema"
    //            });
    //        }
    //        if (!pluginResponse.Success)
    //            return pluginResponse;
    //        foreach (DataRow row in (InternalDataCollectionBase)param.Schema.Rows)
    //        {
    //            try
    //            {
    //                string path = row["JWT_KeyFilePath"].ToString();
    //                if (!string.IsNullOrEmpty(path))
    //                {
    //                    if (File.Exists(path))
    //                    {
    //                        string str1 = row["JWT_Expires"].ToString();
    //                        string str2 = row["JWT_Algorithm"].ToString();
    //                        byte[] numArray = File.ReadAllBytes(path);
    //                        if (numArray.Length < 16)
    //                        {
    //                            pluginResponse.Success = false;
    //                            pluginResponse.Messages.Add(new PluginMessage()
    //                            {
    //                                LogLevel = (LogLevel)30,
    //                                Message = "The key length should be at least 16 characters"
    //                            });
    //                        }
    //                        if (string.IsNullOrEmpty(str1))
    //                        {
    //                            pluginResponse.Success = false;
    //                            pluginResponse.Messages.Add(new PluginMessage()
    //                            {
    //                                LogLevel = (LogLevel)30,
    //                                Message = "JWT_Expires should not be empty"
    //                            });
    //                        }
    //                        else
    //                        {
    //                            if (!str1.All<char>(new System.Func<char, bool>(char.IsDigit)))
    //                            {
    //                                pluginResponse.Success = false;
    //                                pluginResponse.Messages.Add(new PluginMessage()
    //                                {
    //                                    LogLevel = (LogLevel)30,
    //                                    Message = "Expiration timeout should be numeric (seconds)"
    //                                });
    //                            }
    //                            if (int.Parse(str1) < 1)
    //                            {
    //                                pluginResponse.Success = false;
    //                                pluginResponse.Messages.Add(new PluginMessage()
    //                                {
    //                                    LogLevel = (LogLevel)30,
    //                                    Message = "Eexpiry parameter should be a positive number"
    //                                });
    //                            }
    //                        }
    //                        if (string.IsNullOrEmpty(str2))
    //                        {
    //                            pluginResponse.Success = false;
    //                            pluginResponse.Messages.Add(new PluginMessage()
    //                            {
    //                                LogLevel = (LogLevel)30,
    //                                Message = "JWT_Algorithm should not be empty"
    //                            });
    //                        }
    //                        if (pluginResponse.Success)
    //                        {
    //                            DateTime dateTime = DateTime.UtcNow.AddSeconds((double)int.Parse(str1));
    //                            SigningCredentials signingCredentials1 = new SigningCredentials((SecurityKey)new SymmetricSecurityKey(numArray), str2);
    //                            List<Claim> source = new List<Claim>();
    //                            if (param.Schema.Columns.Contains("JWT_Payload_Claims"))
    //                            {
    //                                string str3 = row["JWT_Payload_Claims"].ToString();
    //                                if (!string.IsNullOrEmpty(str3))
    //                                {
    //                                    string str4 = str3;
    //                                    char[] separator = new char[1] { '|' };
    //                                    foreach (string str5 in str4.Split(separator, StringSplitOptions.RemoveEmptyEntries))
    //                                    {
    //                                        string[] strArray = str5.Split(new char[1]
    //                                        {
    //                                           ':'
    //                                        }, StringSplitOptions.RemoveEmptyEntries);
    //                                        if (strArray.Length == 2)
    //                                            source.Add(new Claim(strArray[0], strArray[1]));
    //                                        else
    //                                            pluginResponse.Messages.Add(new PluginMessage()
    //                                            {
    //                                                LogLevel = (LogLevel)20,
    //                                                Message = "Received '" + str5 + "' claim. Expected key/value paramater. Example: Name:John Doe|Email:john@mail.com"
    //                                            });
    //                                    }
    //                                }
    //                            }
    //                            List<Claim> claimList = source.Any<Claim>() ? source : (List<Claim>)null;
    //                            DateTime? nullable1 = new DateTime?(dateTime);
    //                            SigningCredentials signingCredentials2 = signingCredentials1;
    //                            DateTime? nullable2 = new DateTime?();
    //                            DateTime? nullable3 = nullable1;
    //                            SigningCredentials signingCredentials3 = signingCredentials2;
    //                            JwtSecurityToken jwtSecurityToken = new JwtSecurityToken((string)null, (string)null, (IEnumerable<Claim>)claimList, nullable2, nullable3, signingCredentials3);
    //                            JwtSecurityTokenHandler securityTokenHandler = new JwtSecurityTokenHandler();
    //                            row["JWT_Token"] = (object)((SecurityTokenHandler)securityTokenHandler).WriteToken((SecurityToken)jwtSecurityToken);
    //                        }
    //                    }
    //                    else
    //                    {
    //                        pluginResponse.Success = false;
    //                        pluginResponse.Messages.Add(new PluginMessage()
    //                        {
    //                            LogLevel = (LogLevel)30,
    //                            Message = "File '" + path + "' not found"
    //                        });
    //                    }
    //                }
    //            }
    //            catch (Exception ex)
    //            {
    //                pluginResponse.Success = false;
    //                pluginResponse.Messages.Add(new PluginMessage()
    //                {
    //                    LogLevel = (LogLevel)30,
    //                    Message = ex.Message,
    //                    StackTrace = ex.StackTrace
    //                });
    //            }
    //        }
    //        param.Schema.AcceptChanges();
    //        return pluginResponse;
    //    }
    //}
    public class Altshuler_CreateAsymJWT : IPlugin
    {
        public PluginResponse Execute(PluginParam param)
        {
            PluginResponse pluginResponse = new PluginResponse()
            {
                Messages = new List<PluginMessage>(),
                Success = true
            };
            if (param.Schema == null)
                param.Schema = new DataTable();
            if (!param.Schema.Columns.Contains("JWT_KeyFilePath"))
            {
                pluginResponse.Success = false;
                pluginResponse.Messages.Add(new PluginMessage()
                {
                    LogLevel = (LogLevel)30,
                    Message = "'JWT_KeyFilePath' column does not exist in Schema"
                });
            }
            if (!param.Schema.Columns.Contains("JWT_Expires"))
            {
                pluginResponse.Success = false;
                pluginResponse.Messages.Add(new PluginMessage()
                {
                    LogLevel = (LogLevel)30,
                    Message = "'JWT_Expires' column does not exist in Schema"
                });
            }
            if (!param.Schema.Columns.Contains("JWT_Algorithm"))
            {
                pluginResponse.Success = false;
                pluginResponse.Messages.Add(new PluginMessage()
                {
                    LogLevel = (LogLevel)30,
                    Message = "'JWT_Algorithm' column does not exist in Schema"
                });
            }
            if (!param.Schema.Columns.Contains("JWT_Token"))
            {
                pluginResponse.Success = false;
                pluginResponse.Messages.Add(new PluginMessage()
                {
                    LogLevel = (LogLevel)30,
                    Message = "'JWT_Token' column does not exist in Schema"
                });
            }
            if (!pluginResponse.Success)
                return pluginResponse;
            
            if (!param.Schema.Columns.Contains("JWT_Payload_JSON"))
            {
                pluginResponse.Success = false;
                pluginResponse.Messages.Add(new PluginMessage()
                {
                    LogLevel = (LogLevel)30,
                    Message = "'JWT_Payload_JSON' column does not exist in Schema"
                });
            }
            if (!pluginResponse.Success)
                return pluginResponse;

            foreach (DataRow row in (InternalDataCollectionBase)param.Schema.Rows)
            {
                try
                {
                    string path = row["JWT_KeyFilePath"].ToString();
                    Newtonsoft.Json.Linq.JObject JWT_Payload = new Newtonsoft.Json.Linq.JObject();
                    Newtonsoft.Json.Linq.JObject JWT_Header = null;

                    if (!string.IsNullOrEmpty(path))
                    {
                        if (File.Exists(path))
                        {
                            string str1 = row["JWT_Expires"].ToString();
                            string str2 = row["JWT_Algorithm"].ToString();
                            string pem = File.ReadAllText(path);

                            //if (pem.Length < 16)
                            //{
                            //    pluginResponse.Success = false;
                            //    pluginResponse.Messages.Add(new PluginMessage()
                            //    {
                            //        LogLevel = (LogLevel)30,
                            //        Message = "The key length should be at least 16 characters"
                            //    });
                            //}
                            if (string.IsNullOrEmpty(str1))
                            {
                                pluginResponse.Success = false;
                                pluginResponse.Messages.Add(new PluginMessage()
                                {
                                    LogLevel = (LogLevel)30,
                                    Message = "JWT_Expires should not be empty"
                                });
                            }
                            else
                            {
                                if (!str1.All<char>(new System.Func<char, bool>(char.IsDigit)))
                                {
                                    pluginResponse.Success = false;
                                    pluginResponse.Messages.Add(new PluginMessage()
                                    {
                                        LogLevel = (LogLevel)30,
                                        Message = "Expiration timeout should be numeric (seconds)"
                                    });
                                }
                                if (int.Parse(str1) < 1)
                                {
                                    pluginResponse.Success = false;
                                    pluginResponse.Messages.Add(new PluginMessage()
                                    {
                                        LogLevel = (LogLevel)30,
                                        Message = "Eexpiry parameter should be a positive number"
                                    });
                                }
                            }
                            if (string.IsNullOrEmpty(str2))
                            {
                                pluginResponse.Success = false;
                                pluginResponse.Messages.Add(new PluginMessage()
                                {
                                    LogLevel = (LogLevel)30,
                                    Message = "JWT_Algorithm should not be empty"
                                });
                            }
                            if (pluginResponse.Success)
                            {
                                DateTime dateTime = DateTime.UtcNow.AddSeconds((double)int.Parse(str1));

                                if (!string.IsNullOrEmpty(row["JWT_Payload_JSON"].ToString()))
                                {
                                    JWT_Payload = JsonConvert.DeserializeObject<Newtonsoft.Json.Linq.JObject>(row["JWT_Payload_JSON"].ToString());
                                }

                                JWT_Payload["exp"] = Convert.ToInt64((dateTime - DateTime.UtcNow).TotalSeconds);

                                if (param.Schema.Columns.Contains("JWT_Header_Claims"))
                                {
                                    JWT_Header = new Newtonsoft.Json.Linq.JObject();
                                    string str3 = row["JWT_Header_Claims"].ToString();
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
                                            else
                                                pluginResponse.Messages.Add(new PluginMessage()
                                                {
                                                    LogLevel = (LogLevel)20,
                                                    Message = "Received '" + str5 + "' claim. Expected key/value paramater. Example: Name:John Doe|Email:john@mail.com"
                                                });
                                        }
                                    }
                                }

                                //---------------- Create JWT
                                var handler = new JsonWebTokenHandler();
                                var now = DateTime.UtcNow;
                                //string pem = File.ReadAllText(@"C:\Users\User.DESKTOP-GT87VRO\Desktop\Oshry_Iconduct\private.txt"); //private key string;
                                PemReader pr = new PemReader(new StringReader(pem));
                                AsymmetricCipherKeyPair KeyPair = (AsymmetricCipherKeyPair)pr.ReadObject();
                                RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)KeyPair.Private);
                                var rsaProvider = RSA.Create(2048); //It'll compatible with .NET Core v2.2
                                rsaProvider.ImportParameters(rsaParams);
                                var signingKey = new RsaSecurityKey(rsaProvider);
                                var signingCredentials = new SigningCredentials(signingKey, str2);
                                //---------------- Create JWT


                                string token = handler.CreateToken(
                                    JWT_Payload.ToString(),
                                    signingCredentials,
                                    JWT_Header == null ? null : JsonConvert.DeserializeObject<JwtHeader>(JWT_Header.ToString())
                                );

                                row["JWT_Token"] = (object)token;

                                //row["JWT_Token"] = (object)((SecurityTokenHandler)securityTokenHandler).WriteToken((SecurityToken)jwtSecurityToken);
                            }
                        }
                        else
                        {
                            pluginResponse.Success = false;
                            pluginResponse.Messages.Add(new PluginMessage()
                            {
                                LogLevel = (LogLevel)30,
                                Message = "File '" + path + "' not found"
                            });
                        }
                    }
                }
                catch (Exception ex)
                {
                    pluginResponse.Success = false;
                    pluginResponse.Messages.Add(new PluginMessage()
                    {
                        LogLevel = (LogLevel)30,
                        Message = ex.Message,
                        StackTrace = ex.StackTrace
                    });
                }
            }
            param.Schema.AcceptChanges();
            return pluginResponse;
        }
    }
}
