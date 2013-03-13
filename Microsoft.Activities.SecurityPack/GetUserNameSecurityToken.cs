using System.Activities;
using System.ComponentModel;
using System.Drawing;
using System.IdentityModel.Tokens;
using Microsoft.Activities.SecurityPack.Designers;
using Microsoft.Activities.SecurityPack.ToolboxIcons;

namespace Microsoft.Activities.SecurityPack
{
    [Designer(typeof(GetUserNameSecurityTokenDesigner))]
    [ToolboxBitmap(typeof(IconMoniker),"GetUserNameToken")]
    public class GetUserNameSecurityToken : CodeActivity<SecurityToken>
    {
        public InArgument<string> UserName { get; set; }
        public InArgument<string> Password { get; set; }

        protected override void CacheMetadata(CodeActivityMetadata metadata)
        {
            base.CacheMetadata(metadata);
            if (this.UserName == null)
                metadata.AddValidationError(string.Format("The activity '{0}' must specify UserName property.", base.DisplayName));
        }
        protected override SecurityToken Execute(CodeActivityContext context)
        {
            var token = new UserNameSecurityToken(this.UserName.Get(context), this.Password.Get(context));

            return token;
        }
    }
}
