using System.Activities;
using System.ComponentModel;
using System.Drawing;
using System.Runtime.Serialization;
using System.Security;
using System.Security.Permissions;
using System.Security.Principal;
using System.ServiceModel;
using System.ServiceModel.Activities;
using System.ServiceModel.Description;
using System.Threading;
using System.Web.Security;
using System.Windows.Markup;
using Microsoft.Activities.SecurityPack.Designers;
using Microsoft.Activities.SecurityPack.ToolboxIcons;


namespace Microsoft.Activities.SecurityPack
{
    /// <summary>
    /// Enables PrincipalPermission based authorization
    /// </summary>
    [Designer(typeof(PrincipalPermissionScopeDesigner))]
    [ToolboxBitmap(typeof(IconMoniker),"PrincipalPermission")]
    [ContentProperty("Body")]
    public class PrincipalPermissionScope : NativeActivity
    {
        public InArgument<string> PrincipalPermissionName { get; set; }
        public InArgument<string> PrincipalPermissionRole { get; set; }

        public Activity Body { get; set; }

        protected override void CacheMetadata(NativeActivityMetadata metadata)
        {
            var name = new RuntimeArgument("PrincipalPermissionName", typeof(string), ArgumentDirection.In);
            var role = new RuntimeArgument("PrincipalPermissionRole", typeof(string), ArgumentDirection.In);

            metadata.Bind(this.PrincipalPermissionName, name);
            metadata.AddArgument(name);

            metadata.Bind(this.PrincipalPermissionRole, role);
            metadata.AddArgument(role);

            metadata.AddChild(this.Body);
        }

        protected override void Execute(NativeActivityContext context)
        {
            var name = this.PrincipalPermissionName.Get(context);
            var role = this.PrincipalPermissionRole.Get(context);

            var principalPermission = new PrincipalPermission(name, role);
            context.Properties.Add("AuthorizationManager", 
                new AuthorizationManager(principalPermission));

            if (this.Body != null)
                context.ScheduleActivity(this.Body);

            context.Track(new PrincipalPermissionDemandRecord(name, role));
        }


        [DataContract]
        class AuthorizationManager : IReceiveMessageCallback
        {
            [DataMember]
            PrincipalPermission _principalPermission;

            public AuthorizationManager(PrincipalPermission principalPermission)
            {
                this._principalPermission = principalPermission;
            }

            public void OnReceiveMessage(
                OperationContext operationContext, 
                ExecutionProperties activityExecutionProperties)
            {
                if (operationContext != null && operationContext.ServiceSecurityContext != null)
                {
                    //saving current principal for later restoration.
                    var currentPrincipal = Thread.CurrentPrincipal;
                    var isPrincipalSet = false;
                    var targetPrincipal = GetPrincipal(operationContext);
                    try
                    {
                        if (targetPrincipal != null)
                        {
                            Thread.CurrentPrincipal = targetPrincipal;
                            isPrincipalSet = true;

                            _principalPermission.Demand();
                        }

                    }
                    catch (SecurityException)
                    {
                        throw SecurityUtility.CreateAccessDeniedFaultException();
                    }
                    finally
                    {
                        if (isPrincipalSet)
                            Thread.CurrentPrincipal = currentPrincipal;

                    }
                }
                else // if there is no security information available in the incoming, access should be denied.
                {
                    throw SecurityUtility.CreateAccessDeniedFaultException();
                }
            }
            IPrincipal GetPrincipal(OperationContext operationContext)
            {
                ServiceSecurityContext securityContext = operationContext.ServiceSecurityContext;
                PrincipalPermissionMode principalPermissionMode = operationContext.EndpointDispatcher.DispatchRuntime.PrincipalPermissionMode;
                var roleProvider = operationContext.EndpointDispatcher.DispatchRuntime.RoleProvider;

                IPrincipal targetPrincipal = null;
                if (principalPermissionMode == PrincipalPermissionMode.UseWindowsGroups)
                {
                    targetPrincipal = new WindowsPrincipal(securityContext.WindowsIdentity);
                }
                else if (principalPermissionMode == PrincipalPermissionMode.UseAspNetRoles)
                {
                    targetPrincipal = new RoleProviderPrincipal(securityContext.PrimaryIdentity, roleProvider);
                }
                else if (principalPermissionMode == PrincipalPermissionMode.Custom)
                {
                    object obj = null;
                    if (securityContext.AuthorizationContext.Properties.TryGetValue("Principal", out obj))
                        targetPrincipal = (IPrincipal)obj;
                }

                return targetPrincipal;

            }

            static class SecurityUtility
            {
                public static FaultException CreateAccessDeniedFaultException()
                {
                    FaultCode code = FaultCode.CreateSenderFaultCode("FailedAuthentication",
                        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
                    return new FaultException(new FaultReason("Access is denied"), code);
                }
            }

            class RoleProviderPrincipal : IPrincipal
            {
                readonly IIdentity _identity;
                readonly RoleProvider _roleProvider;

                public RoleProviderPrincipal(IIdentity identity, RoleProvider roleProvider)
                {
                    this._identity = identity;
                    this._roleProvider = roleProvider;
                }

                public IIdentity Identity
                {
                    get { return this._identity; }
                }

                public bool IsInRole(string role)
                {
                    return ((_roleProvider != null) && _roleProvider.IsUserInRole(this._identity.Name, role));
                }

            }

        }
    }
}
