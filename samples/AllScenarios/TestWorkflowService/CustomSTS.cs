using System;
using System.Linq;
using System.IdentityModel;
using System.IdentityModel.Configuration;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Security;
using Extensions.Utilities;


namespace TestWorkflowService
{
    class CustomSecurityTokenService : SecurityTokenService
    {
        public CustomSecurityTokenService(SecurityTokenServiceConfiguration config)
            : base(config)        {   
        }

        protected override Scope GetScope(ClaimsPrincipal principal, RequestSecurityToken request)
        {
            var appliesTo = request.AppliesTo.Uri.AbsoluteUri;
            Scope scope = new Scope(appliesTo, SecurityTokenServiceConfiguration.SigningCredentials);

            scope.ReplyToAddress = request.ReplyTo;
            if (string.IsNullOrEmpty(scope.ReplyToAddress))
                scope.ReplyToAddress = request.AppliesTo.Uri.AbsoluteUri;

            scope.EncryptingCredentials = new X509EncryptingCredentials(GetRPCert(request.AppliesTo.Uri));
            return scope;
        }

        private static X509Certificate2 GetRPCert(Uri appliesTo)
        {
            switch (appliesTo.AbsoluteUri)
            {
                default:
                    return new X509Certificate2("localhost.cer");
            }
        }

        void ValidateAppliesTo(EndpointAddress appliesTo)
        {
            if (appliesTo == null)
            {
                throw new InvalidRequestException("The appliesTo is null.");
            }
        }

        public override RequestSecurityTokenResponse Issue(ClaimsPrincipal principal, RequestSecurityToken request)
        {
            Diagnostics.Trace.TraceInformation("Issuing token...");
            var token = base.Issue(principal, request);
            return token;
        }

        protected override ClaimsIdentity GetOutputClaimsIdentity(ClaimsPrincipal principal, RequestSecurityToken request, Scope scope)
        {
            // ValidateAppliesTo(request.AppliesTo);


            // Create new identity and copy content of the caller's identity into it (including the existing delegate chain)
            var callerIdentity = (ClaimsIdentity)principal.Identity;
            var outputIdentity = callerIdentity.Clone();


            // If there is an ActAs token in the RST, return a copy of it as the top-most identity
            // and put the caller's identity into the Actor property of this identity.
            if (request.ActAs != null)
            {
                ClaimsIdentity actAsIdentity = request.ActAs.GetIdentities()[0];

                // Find the last actor in the actAs identity
                ClaimsIdentity lastActor = actAsIdentity;
                while (lastActor.Actor != null)
                {
                    lastActor = lastActor.Actor;
                }

                // Set the caller's identity as the last actor in the delegation chain
                lastActor.Actor = outputIdentity;

                // Return the actAsIdentity instead of the caller's identity in this case
                outputIdentity = actAsIdentity;
                Diagnostics.Trace.TraceInformation("Creating ActAs claims...");
            }
            if (!outputIdentity.Claims.Any()) //add hardcoded claims...
                outputIdentity.AddClaims(new[]
                                             {
                                                 new Claim(System.IdentityModel.Claims.ClaimTypes.Name, "Zulfiqar"),
                                                 new Claim(System.IdentityModel.Claims.ClaimTypes.Email, "zamd@ms.com"),
                                                 new Claim(System.IdentityModel.Claims.ClaimTypes.Upn,
                                                           "zuahmed@microsoft.com"),
                                             });
            return outputIdentity;
        }
    }

    // custom contract implementation to handle errors etc...
    class MyWSTrustContract : WSTrustServiceContract
    {
        public MyWSTrustContract(SecurityTokenServiceConfiguration config):base(config)
        {

        }
        protected override bool HandleException(Exception ex, string trustNamespace, string action, EnvelopeVersion requestEnvelopeVersion)
        {
            Diagnostics.Trace.TraceError(ex.Message);
            
            return base.HandleException(ex, trustNamespace, action, requestEnvelopeVersion);
        }
    }
}