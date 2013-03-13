using System;
using System.Activities;
using System.ComponentModel;
using System.Drawing;
using System.IdentityModel.Tokens;
using Microsoft.Activities.SecurityPack.Designers;
using Microsoft.Activities.SecurityPack.ToolboxIcons;

namespace Microsoft.Activities.SecurityPack
{
    public abstract class TokenHandler : CodeActivity
    {
        public InArgument<SecurityTokenHandle> TokenHandle { get; set; }
        protected SecurityTokenHandle Handle;

        protected void EnsureHandle(CodeActivityContext context)
        {
            // Try getting ambiant handle
            Handle = context.GetProperty<SecurityTokenHandle>();
            if (Handle == null && this.TokenHandle != null)
                Handle = this.TokenHandle.Get(context);

            if (Handle == null)
                throw new InvalidOperationException(
                    string.Format("TokenHandle property must be set to a valid SecurityTokenHandle or '{0}' must be inside a TokenFlowScope activity.", this.DisplayName));
        }
    }

    [Designer(typeof(InitializeUserNameSecurityTokenDesigner))]
    [ToolboxBitmap(typeof(IconMoniker), "InitializeUserNameToken")]
    public class InitializeUserNameSecurityToken : TokenHandler
    {
        public InArgument<string> UserName { get; set; }
        public InArgument<string> Password { get; set; }

        protected override void CacheMetadata(CodeActivityMetadata metadata)
        {
            base.CacheMetadata(metadata);
            if (this.UserName == null)
                metadata.AddValidationError(string.Format("The activity '{0}' must specify UserName property.", base.DisplayName));
        }
        protected override void Execute(CodeActivityContext context)
        {
            base.EnsureHandle(context);
            var token = new UserNameSecurityToken(this.UserName.Get(context), this.Password.Get(context));
            Handle.EnlistToken(token);
        }
    }
}
