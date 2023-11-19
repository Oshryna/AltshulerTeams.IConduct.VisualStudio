using IConduct.SDK.v2;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;

namespace IConduct.Plugins.JWT
{
    public class IConductJwtValidation : IPlugin
    {
        private bool IsValid(string token, double remainingSeconds, string timeComparingType, out JObject josn)
        {
            josn = null;
            JwtSecurityToken jwtSecurityToken;
            try
            {
                jwtSecurityToken = new JwtSecurityToken(token);
            }
            catch (Exception)
            {
                return false;
            }

            josn = new JObject(
                    new JProperty("HEADER", Newtonsoft.Json.Linq.JObject.FromObject(jwtSecurityToken.Header)),
                    new JProperty("PAYLOAD", Newtonsoft.Json.Linq.JObject.FromObject(jwtSecurityToken.Payload))
                );

            switch (timeComparingType.ToLower())
            {
                case "s":
                    return jwtSecurityToken.ValidTo > DateTime.UtcNow.AddSeconds(remainingSeconds);
                case "m":
                    return jwtSecurityToken.ValidTo > DateTime.UtcNow.AddMinutes(remainingSeconds);
                case "h":
                    return jwtSecurityToken.ValidTo > DateTime.UtcNow.AddHours(remainingSeconds);
                default:
                    return false;
            }            
        }
        public PluginResponse Execute(PluginParam param)
        {
            string timeComparingType = "s";
            string token;
            string remainingSeconds;
            string json;
            JObject j;

            PluginResponse pluginResponse = new PluginResponse()
            {
                Messages = new List<PluginMessage>(),
                Success = true
            };
            if (param.Schema == null)
                param.Schema = new DataTable();
            if (!param.Schema.Columns.Contains("JWT_Token"))
            {
                pluginResponse.Success = false;
                pluginResponse.Messages.Add(new PluginMessage()
                {
                    LogLevel = (LogLevel)30,
                    Message = "'JWT_Token' column does not exist in Schema"
                });
            }
            if (!param.Schema.Columns.Contains("JWT_RemainingTime"))
            {
                pluginResponse.Success = false;
                pluginResponse.Messages.Add(new PluginMessage()
                {
                    LogLevel = (LogLevel)30,
                    Message = "'JWT_RemainingTime' column does not exist in Schema"
                });
            }
            if (!param.Schema.Columns.Contains("JWT_IsValid"))
            {
                pluginResponse.Success = false;
                pluginResponse.Messages.Add(new PluginMessage()
                {
                    LogLevel = (LogLevel)30,
                    Message = "'JWT_IsValid' column does not exist in Schema"
                });
            }
            if (!pluginResponse.Success)
                return pluginResponse;
            foreach (DataRow row in (InternalDataCollectionBase)param.Schema.Rows)
            {
                if (param.Schema.Columns.Contains("JWT_TimeComparingType") && 
                    !String.IsNullOrEmpty(row["JWT_TimeComparingType"].ToString()) &&
                    new[] { "s", "m", "h" }.Contains(row["JWT_TimeComparingType"].ToString()))
                {
                    timeComparingType = row["JWT_TimeComparingType"].ToString();
                }
                try
                {
                    token = row["JWT_Token"].ToString();
                    remainingSeconds = row["JWT_RemainingTime"].ToString();
                    
                    row["JWT_IsValid"] = (object)IsValid(token, double.Parse(remainingSeconds), timeComparingType, out j);

                    if (param.Schema.Columns.Contains("JWT_DecodedToken") && j != null)
                    {
                        row["JWT_DecodedToken"] = (object)j.ToString();
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
