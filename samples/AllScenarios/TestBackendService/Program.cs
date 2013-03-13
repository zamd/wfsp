using System;
using System.Linq;
using System.Security.Claims;
using System.ServiceModel;
using System.ServiceModel.Description;
using System.Threading;
using Extensions.Utilities;
using System.Security.Cryptography.X509Certificates;
using System.IdentityModel.Tokens;
using System.IdentityModel.Selectors;
using System.ServiceModel.Security;


[ServiceContract]
public interface ITransformerService
{
    [OperationContract]
    string Transform(string input);
}

public class TransformerService : ITransformerService
{
    public string Transform(string input)
    {
        var claimsIdentity = Thread.CurrentPrincipal.Identity as ClaimsIdentity;
        if (claimsIdentity != null)
            PrintCallerIdentity(claimsIdentity);
        else
            Console.WriteLine("No claims found in the incomming security context.");
        return input.ToUpper();
    }

    void PrintCallerIdentity(ClaimsIdentity identity)
    {
        Console.WriteLine("Caller's name: " + identity.Name);
        PrintClaims(identity);
        while (identity.Actor != null)
        {
            Console.WriteLine("Acting Via: " + identity.Actor.Name);
            PrintClaims(identity.Actor);
            identity = identity.Actor;
        }

        Console.WriteLine();
    }

    private static void PrintClaims(ClaimsIdentity identity)
    {
        //filter groupsid claims....
        identity.Claims.Where(c => c.Type != ClaimTypes.GroupSid).ToList().ForEach(c =>
        {
            Console.WriteLine("ClaimType  : " + c.Type.Split('/').Last());
            Console.WriteLine("ClaimValue : " + c.Value);
            Console.WriteLine();
        });
    }
}


namespace TestBackendService
{
    static class Transforms
    {
        public static readonly Transform DefaultServiceCertificate = new Transform("SetupServiceCertificate", host =>
        {
            host.Credentials.ServiceCertificate.Certificate = new X509Certificate2("localhost.pfx", "a");
        });

        public static readonly Transform MetadataViaHttpGet = new Transform("ConfigureMetadataViaHttpGet", host =>
        {
            host.ConfigureMetadataViaHttpGet();
        });

    }


    class Program
    {
        static void Main(string[] args)
        {
            var mgr = new ServiceHostManager(9090);
            var h1 = mgr.RegisterService(typeof(TransformerService));
            mgr.AddTransform(h1, GetWIFTransform());
            mgr.AddTransform(h1, Transforms.MetadataViaHttpGet);

            mgr.Open();

            Console.WriteLine("Host(s) ready. Hit Enter to close.");
            Console.ReadLine();
            mgr.Close();

        }

        private static Transform GetWIFTransform()
        {
            return new Transform(host =>
                                     {
                                         //need to figure out why this doesn't work with WIF programming model
                                         host.Credentials.ServiceCertificate.Certificate = new X509Certificate2("localhost.pfx", "a");
                                         host.Authorization.PrincipalPermissionMode = PrincipalPermissionMode.Always;
                                         
                                         host.Credentials.UseIdentityConfiguration = true;
                                         host.Credentials.IdentityConfiguration.SaveBootstrapContext = true;
                                         host.Credentials.IdentityConfiguration.ServiceCertificate =
                                             new X509Certificate2("localhost.pfx", "a");
                                         host.Credentials.IdentityConfiguration.AudienceRestriction =
                                             new AudienceRestriction(AudienceUriMode.Never);
                                         host.Credentials.IdentityConfiguration.IssuerNameRegistry =
                                             new TrustAllRegistry();
                                         host.Credentials.IdentityConfiguration.CertificateValidationMode =
                                             X509CertificateValidationMode.None;
                                     });
        }
    }
    class TrustAllRegistry : IssuerNameRegistry
    {
        public override string GetIssuerName(SecurityToken securityToken)
        {
            return "TestingOnly - AllTrusted";
        }
    }
}
