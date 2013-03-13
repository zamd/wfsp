using System;
using System.Activities;
using System.ComponentModel;
using System.Drawing;
using System.IdentityModel.Configuration;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Security.Claims;
using System.Security.Principal;
using System.ServiceModel;
using System.ServiceModel.Activities;
using System.Text;
using System.Windows.Markup;
using Microsoft.Activities.SecurityPack.Designers;
using Microsoft.Activities.SecurityPack.ToolboxIcons;

namespace Microsoft.Activities.SecurityPack
{
    [Designer(typeof(ImpersonatingReceiveScopeDesigner))]
    [ToolboxBitmap(typeof(IconMoniker), "ImpersonatingReceive")]
    [ContentProperty("Body")]
    public class ImpersonatingReceiveScope : NativeActivity
    {
        public Activity Body { get; set; }

        protected override void Execute(NativeActivityContext context)
        {
            if (this.Body != null)
            {
                context.Properties.Add(IdentityHandle.PropertyName, new IdentityHandle());
                context.ScheduleActivity(this.Body);
            }
        }


        [DataContract]
        class IdentityHandle : Handle, IReceiveMessageCallback, IExecutionProperty
        {
            public static readonly string PropertyName = typeof(IdentityHandle).FullName;

            [DllImport("secur32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            private static extern byte GetUserNameEx(int format, StringBuilder domainName, ref int domainNameLen);
            private WindowsImpersonationContext _impersonationContext;
            private WindowsIdentity windowsIdentity;
            private bool readyToImpersonate;

            // Upn will be used to re-create a WindowsIdentity after a persistence episode.
            [DataMember]
            string impersonatedUpn;

            public void OnReceiveMessage(OperationContext operationContext, ExecutionProperties activityExecutionProperties)
            {
                if (operationContext != null && operationContext.ServiceSecurityContext != null)
                {
                    var claimsIdentity = operationContext.GetClaimsIdentity();
                    windowsIdentity = claimsIdentity as WindowsIdentity;
                    if (!(this.windowsIdentity != null && this.windowsIdentity.IsAuthenticated))
                    {
                        //no valid WindowsIdentity found, look for UPN claim in incoming identity and use that to
                        // create a new WindowsIdentity using S4U feature.
                        var upnClaim = claimsIdentity.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Upn);
                        if (upnClaim != null)
                            impersonatedUpn = upnClaim.Value;
                    }

                    readyToImpersonate = true;
                }
            }

            public void CleanupWorkflowThread()
            {
                if (_impersonationContext != null)
                {
                    _impersonationContext.Dispose();
                    _impersonationContext = null;
                }
            }

            public void SetupWorkflowThread()
            {
                if (!readyToImpersonate)
                    return;
                if (windowsIdentity == null || !windowsIdentity.IsAuthenticated)
                {
                    if (!string.IsNullOrEmpty(impersonatedUpn))
                    {
                        try
                        {
                            //TODO: TokenImpersonationLevel would probably be get out of sync with this approach.
                            // WIF service, returns the identity with TokenImpersonationLevel set to Impersonation which might not be the same as the orignal identity.
                            windowsIdentity = S4UClient.UpnLogon(impersonatedUpn);
                        }
                        catch (Exception exp)
                        {
                            throw new Exception(string.Format(SR.S4ULoginFailed, impersonatedUpn), exp);
                        }
                    }
                }

                if (windowsIdentity == null || !windowsIdentity.IsAuthenticated)
                    throw new InvalidOperationException("Impersonation failed as no valid WindowsIdentity found and there is no Upn claim in the incomming token.");

                _impersonationContext = windowsIdentity.Impersonate();

                if (string.IsNullOrEmpty(impersonatedUpn))
                {
                    // Get the UPN from the impersonation token.
                    var upn = new StringBuilder(0x400);
                    int capacity = upn.Capacity;
                    if (GetUserNameEx(8, upn, ref capacity) == 1)
                        this.impersonatedUpn = upn.ToString();
                }
            }

        }
    }

    [Designer(typeof(ImpersonateTokenScopeDesigner))]
    [ToolboxBitmap(typeof(IconMoniker), "ImpersonateTokenScope")]
    public sealed class ImpersonateTokenScope : NativeActivity, IExecutionProperty
    {
        private WindowsImpersonationContext _impersonationContext;
        private WindowsIdentity _identity;

        public InArgument<SecurityTokenHandle> TokenHandle { get; set; }
        public ActivityFunc<SecurityToken> Initializer { get; set; }

        public Activity Body { get; set; }

        protected override void CacheMetadata(NativeActivityMetadata metadata)
        {
            base.CacheMetadata(metadata);
            if (this.Initializer == null || this.Initializer.Handler == null)
            {
                metadata.AddValidationError(string.Format("The activity '{0}' must specify a token initializer.",
                     base.DisplayName));
            }
            else if (!(this.Initializer.Handler is Activity<SecurityToken>))
            {
                metadata.AddValidationError(string.Format("The activity '{0}' has an invalid token initializer. Please specify an intitializer of type {1}.",
                     base.DisplayName, "Activity<SecurityToken>"));
            }
        }
        protected override void Execute(NativeActivityContext context)
        {
            context.ScheduleFunc<SecurityToken>(this.Initializer, OnCompleted);
        }

        void OnCompleted(NativeActivityContext context, ActivityInstance completedInstance, SecurityToken token)
        {
            var handler = new SecurityTokenServiceConfiguration().SecurityTokenHandlers[token];
            if (handler != null)
            {
                var claimsIdentityCol = handler.ValidateToken(token);

                foreach (var ci in claimsIdentityCol)
                {
                    if (ci is WindowsIdentity)
                    {
                        _identity = (WindowsIdentity)ci;
                        context.Properties.Add("Testing", this);
                        break;
                    }
                }
                context.ScheduleActivity(this.Body);
            }
        }



        public void CleanupWorkflowThread()
        {
            if (_impersonationContext != null)
            {
                _impersonationContext.Dispose();
                _impersonationContext = null;
            }
        }

        public void SetupWorkflowThread()
        {
            if (_identity != null && _identity.IsAuthenticated)
            {
                _impersonationContext = _identity.Impersonate();
            }
        }
    }
}
