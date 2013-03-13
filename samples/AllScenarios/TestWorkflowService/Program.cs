using System;
using System.IdentityModel.Configuration;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Security;
using Extensions.Utilities;
using System.ServiceModel.Activities.Description;
using System.Linq;

public class SimpleUserNamePasswordValidator : UserNamePasswordValidator
{
    public override void Validate(string userName, string password)
    {
        Diagnostics.Trace.TraceInformation("[Success]: {0} authenticated.", userName);
    }
}
[ServiceContract]
public interface IPingService
{
    [OperationContract(IsOneWay = true)]
    void Ping();
}

class PingService : IPingService
{
    public void Ping()
    {
        var remote = OperationContext.Current.IncomingMessageProperties[RemoteEndpointMessageProperty.Name] as RemoteEndpointMessageProperty;
        Console.WriteLine("Ping from {0}:{1}", remote.Address, remote.Port);
        Console.WriteLine("Secure conversation session, SessionID = {0}", OperationContext.Current.SessionId);


        if (OperationContext.Current.ServiceSecurityContext != null && 
            OperationContext.Current.ServiceSecurityContext.AuthorizationContext != null && 
            OperationContext.Current.ServiceSecurityContext.AuthorizationContext.ClaimSets != null)
        {
            Console.WriteLine("Claims");
            Console.WriteLine("======");
            foreach (var cs in OperationContext.Current.ServiceSecurityContext.AuthorizationContext.ClaimSets)
            {
                foreach (var claim in cs)
                {
                    Console.WriteLine("ClaimType='{0}', Value ='{1}'", claim.ClaimType.Split('/').Last(), claim.Resource);
                }
            }
        }

        
    }
}

namespace TestWorkflowService
{
    static class Transforms
    {
        public static readonly Transform DefaultServiceCertificate = new Transform("SetupServiceCertificate", host =>
        {
            host.Credentials.ServiceCertificate.Certificate = new X509Certificate2("localhost.pfx", "a");
        });

        public static readonly Transform CustomUserNamePasswordAuth = new Transform("SetupCustomUserNamePasswordAuth", host =>
        {
            host.Credentials.UserNameAuthentication.UserNamePasswordValidationMode = UserNamePasswordValidationMode.Custom;
            host.Credentials.UserNameAuthentication.CustomUserNamePasswordValidator = new SimpleUserNamePasswordValidator();
        });

        public static readonly Transform STSProlog = new Transform(ServiceHostManager.Prolog, host =>
        {
            Console.WriteLine("STS Host.");
            Console.WriteLine("<========================");
        });

    }

    class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            var mgr = new ServiceHostManager();

            //PrincipalPermission
            mgr.RegisterActivity(new PrincipalPermissionWorkflow());

            var h2 = mgr.RegisterService(typeof(PingService));
            mgr.AddTransform(h2, Transforms.DefaultServiceCertificate);
            mgr.AddTransform(h2, Transforms.CustomUserNamePasswordAuth);

            var stsHost = GetSTSHost(new Uri("http://localhost:9000/STS"));
            mgr.RegisterHost(stsHost);
            mgr.AddTransform(stsHost, Transforms.STSProlog);

            //Identity delegation test: This workflow will flow client's identity to a system using Claims.
            //This form of delegation doesn't require any infrastructure changes at all.
            var h3 = mgr.RegisterActivity(new IdentityDelegation());
            mgr.AddTransform(h3, GetWIFTransform());


            //Impersonation
            mgr.RegisterActivity(new WindowsImpersonationTest());

            var h4 = mgr.RegisterActivity(new ClaimsImpersonationTest());
            mgr.AddTransform(h4, GetWIFTransform());
            //mgr.AddTransform(h4, Transforms.DefaultServiceCertificate);
            //h4.Credentials.IssuedTokenAuthentication.AllowUntrustedRsaIssuers = true;
            //h4.Credentials.IssuedTokenAuthentication.AudienceUriMode = AudienceUriMode.Never;
            //h4.Credentials.IssuedTokenAuthentication.CertificateValidationMode = X509CertificateValidationMode.None;

            var h5 = mgr.RegisterActivity(new TokensInLongRunningScenarios());
            mgr.AddTransform(h5, GetWIFTransform());
            //apply persist transform
            mgr.AddTransform(h5, wfsh =>
            {
                wfsh.Description.Behaviors.Add(new SqlWorkflowInstanceStoreBehavior(@"Data Source=.\sqlexpress;Initial Catalog=NET45InstanceStore;Integrated Security=True"));
                wfsh.Description.Behaviors.Add(new WorkflowIdleBehavior { TimeToPersist = TimeSpan.FromSeconds(2), TimeToUnload = TimeSpan.FromSeconds(3) });
            });

            mgr.Open();
            Console.WriteLine("Host(s) ready. Enter to terminate process.");
            Console.ReadLine();
            mgr.Close();
        }

        private static Transform GetWIFTransform()
        {
            var userNameHandler = new CustomUserNameSecurityTokenHandler
                                      {
                                          UserNamePasswordValidator =
                                              (userName, password) => Console.WriteLine("{0} authenticated.", userName)
                                      };
            return new Transform(host =>
                                     {
                                         {
                                             //need to figure out why this doesn't work with WIF programming model
                                             host.Credentials.ServiceCertificate.Certificate = new X509Certificate2("localhost.pfx", "a");
                                             host.Authorization.PrincipalPermissionMode = PrincipalPermissionMode.Always;
                                             host.Credentials.UseIdentityConfiguration = true;
                                             var identityConfig = host.Credentials.IdentityConfiguration;
                        
                                             identityConfig.SaveBootstrapContext = true;
                                             identityConfig.AudienceRestriction =
                                                 new AudienceRestriction(AudienceUriMode.Never);
                                             identityConfig.IssuerNameRegistry = new TrustAllRegistry();
                                             identityConfig.CertificateValidationMode =
                                                 X509CertificateValidationMode.None;
                                             //Replace the default UserNamePasswordTokenHandler as it validates the UserName/Password as a windows identity
                                             identityConfig.SecurityTokenHandlers.AddOrReplace(userNameHandler);
                                         }
                                     }
                );
        }

        static ServiceHostBase GetSTSHost(Uri stsAddress)
        {
            X509Certificate2 stsSignCert = new X509Certificate2("localhost.pfx", "a");

            SecurityTokenServiceConfiguration stsConfig =
                new SecurityTokenServiceConfiguration("http://zamd.net", new X509SigningCredentials(stsSignCert))
                {
                    SecurityTokenService = typeof(CustomSecurityTokenService),

                    //following 3 settings are only valid incase of SAML input token.
                    //AudienceUriMode.Never is only meant for testing & must NOT be used in production.
                    AudienceRestriction = new AudienceRestriction(AudienceUriMode.Never),
                    CertificateValidationMode= X509CertificateValidationMode.None,
                    IssuerNameRegistry = new TrustAllRegistry(),
                };

            var userNameHandler = new CustomUserNameSecurityTokenHandler
            {
                UserNamePasswordValidator = delegate(string userName, string password)
                {
                    Console.WriteLine("{0} authenticated.", userName);
                }

            };
            //Replace the default UserNamePasswordTokenHandler as it validates the UserName/Password as a windows identity
            stsConfig.SecurityTokenHandlers.AddOrReplace(userNameHandler);

            SecurityTokenHandler[] actAsHandler = new SecurityTokenHandler[stsConfig.SecurityTokenHandlers.Count];
            stsConfig.SecurityTokenHandlers.CopyTo(actAsHandler, 0);
            stsConfig.SecurityTokenHandlerCollectionManager[SecurityTokenHandlerCollectionManager.Usage.ActAs] = new SecurityTokenHandlerCollection(actAsHandler);

            // host STS as WS-Trust endpoint.
            WSTrustServiceHost stsHost = new WSTrustServiceHost(new MyWSTrustContract(stsConfig), stsAddress);
            var bid = new WSHttpBinding("stsTrustFeb2005");
            stsHost.AddServiceEndpoint(typeof(IWSTrustFeb2005SyncContract), bid, stsAddress);

            var builder = new UriBuilder(stsAddress);
            builder.Path = "Trust13/STS";
            stsHost.AddServiceEndpoint(typeof(IWSTrust13SyncContract), new WSHttpBinding("stsTrust13"), builder.Uri);
            stsHost.Credentials.ServiceCertificate.Certificate = stsSignCert;

            return stsHost;
        }
    }

    public class TrustAllRegistry : IssuerNameRegistry
    {
        public override string GetIssuerName(SecurityToken securityToken)
        {
            return "TestingOnly - AllTrusted";
        }
    }

}
