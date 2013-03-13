using System.Security.Claims;
using System.ServiceModel;

namespace Microsoft.Activities.SecurityPack
{
    public static class OperationContextExtensions
    {
        public static ClaimsIdentity GetClaimsIdentity(this OperationContext source)
        {
            if (source.ServiceSecurityContext == null)
                return null;

            if (source.Host.Credentials.UseIdentityConfiguration)
                return GetPrimaryWifIdentity(source);

            var claimsIdentity = source.ServiceSecurityContext.PrimaryIdentity as ClaimsIdentity;

            return claimsIdentity.IsAuthenticated ? claimsIdentity : null;
        }


        private static ClaimsIdentity GetPrimaryWifIdentity(OperationContext operationContext)
        {
            object claimsPrincipal;
            if ((operationContext.ServiceSecurityContext.AuthorizationContext.Properties.TryGetValue("ClaimsPrincipal",
                                                                                                     out claimsPrincipal)))
            {
                var principal = claimsPrincipal as ClaimsPrincipal;
                if (principal != null && principal.Identity.IsAuthenticated)
                {
                    return (ClaimsIdentity)principal.Identity;
                }
            }

            return null;
        }
    }
}
