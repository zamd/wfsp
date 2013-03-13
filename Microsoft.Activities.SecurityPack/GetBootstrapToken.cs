using System.Activities;
using System.ComponentModel;
using System.Drawing;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.ServiceModel;
using Microsoft.Activities.SecurityPack.Designers;
using Microsoft.Activities.SecurityPack.ToolboxIcons;
using System;
using System.Linq;

namespace Microsoft.Activities.SecurityPack
{
    /// <summary>
    /// Returns a bootstrap token from the incoming message's SecurityContext
    /// </summary>
    [ToolboxBitmap(typeof (IconMoniker), "GetBootstrapToken")]
    [Designer(typeof (GetBootstrapTokenDesigner))]
    public class GetBootstrapToken : CodeActivity<SecurityToken>
    {
        protected override SecurityToken Execute(CodeActivityContext context)
        {
            ClaimsIdentity claimsIdentity = null;
            if (OperationContext.Current != null)
                claimsIdentity = OperationContext.Current.GetClaimsIdentity();

            if (claimsIdentity != null && claimsIdentity.BootstrapContext != null)
                return ((BootstrapContext) claimsIdentity.BootstrapContext).SecurityToken;

            throw new InvalidOperationException(
                "No Bootstrap token found either in OperationContext or Thread Context. Please make sure, 'saveBootstrapTokens' is set to true.");
        }
    }
}
