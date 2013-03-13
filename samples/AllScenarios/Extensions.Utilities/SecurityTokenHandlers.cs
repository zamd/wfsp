using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.IdentityModel.Tokens;
using System.Xml;

namespace Extensions.Utilities
{
    //Enables callback based UserName/Password validation - Similar to WCF UserNamePasswordValidator.
    public class CustomUserNameSecurityTokenHandler : UserNameSecurityTokenHandler
    {
        public Action<string, string> UserNamePasswordValidator { get; set; }
        public CustomUserNameSecurityTokenHandler()
        {
            base.RetainPassword = true;
        }
        public override bool CanValidateToken
        {
            get
            {
                return true;
            }
        }

        public override ReadOnlyCollection<ClaimsIdentity> ValidateToken(SecurityToken token)
        {
            var userNameToken = token as UserNameSecurityToken;
            if (userNameToken == null)
                throw new ArgumentException("Invalid token argument.");

            if (this.UserNamePasswordValidator == null)
            {
                Diagnostics.Trace.TraceWarning("Custom validator is missing. UserNameSecurityToken cannot be validated.");
                throw new InvalidOperationException("Custom validator is missing. " +
                    "Please specify your custom validator using the UserNamePasswordValidator property of CustomUserNameSecurityTokenHandler");
            }

            this.UserNamePasswordValidator(userNameToken.UserName, userNameToken.Password);

            var identity = new ClaimsIdentity(
                new[]
                    {
                        new Claim(ClaimTypes.Name, userNameToken.UserName),
                        new Claim(ClaimTypes.AuthenticationInstant,
                                  XmlConvert.ToString(DateTime.UtcNow,
                                                      "yyyy-MM-ddTHH:mm:ss.fffZ"),
                                  ClaimValueTypes.DateTime),
                        new Claim(ClaimTypes.AuthenticationMethod,
                                  AuthenticationMethods.Password)
                    }, AuthenticationTypes.Password);
   
            if (base.Configuration.SaveBootstrapContext)
            {
                if (this.RetainPassword)
                {
                    identity.BootstrapContext = new BootstrapContext(userNameToken, this);
                }
                else
                {
                    identity.BootstrapContext =
                        new BootstrapContext(new UserNameSecurityToken(userNameToken.UserName, null), this);
                }
            }
            return new List<ClaimsIdentity>(1) {identity}.AsReadOnly();
        }

    }
}
