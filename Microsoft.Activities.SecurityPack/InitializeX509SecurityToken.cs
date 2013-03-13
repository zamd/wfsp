using System;
using System.Activities;
using System.ComponentModel;
using System.Drawing;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using System.Windows.Markup;
using Microsoft.Activities.SecurityPack.Designers;
using Microsoft.Activities.SecurityPack.ToolboxIcons;

namespace Microsoft.Activities.SecurityPack
{
    [ToolboxBitmap(typeof(IconMoniker), "InitializeX509Token")]
    [Designer(typeof(InitializeX509SecurityTokenDesigner))]
    [ContentProperty("FindValue")]
    public class InitializeX509SecurityToken : TokenHandler
    {
        public InitializeX509SecurityToken()
        {
            FindType = X509FindType.FindBySubjectName;
            StoreLocation = StoreLocation.CurrentUser;
            StoreName = System.Security.Cryptography.X509Certificates.StoreName.My;
        }

        protected override void CacheMetadata(CodeActivityMetadata metadata)
        {
            base.CacheMetadata(metadata);


            if (this.Certificate == null && this.FindValue == null)
            {
                metadata.AddValidationError(string.Format("The activity '{0}' must specify either the Certificate or FindValue property.",
                        base.DisplayName));
            }
        }

        public InArgument<X509Certificate2> Certificate { get; set; }

        public X509FindType FindType { get; set; }

        public StoreLocation StoreLocation { get; set; }

        public InArgument<string> FindValue { get; set; }

        public StoreName StoreName { get; set; }

        protected override void Execute(CodeActivityContext context)
        {
            X509Certificate2 targetCert = null;
            if (this.Certificate != null)
                targetCert = this.Certificate.Get(context);

            if (targetCert == null)
            {
                var store = new X509Store(StoreName, StoreLocation);
                try
                {
                    store.Open(OpenFlags.ReadOnly);
                    var col = store.Certificates.Find(FindType, FindValue.Get(context), false);
                    if (col.Count > 0)
                        targetCert = col[0];//Use first certificate mathing the search criteria
                }
                finally
                {
                    if (store != null)
                        store.Close();
                }
            }

            if (targetCert == null)
                throw new InvalidOperationException("No certificate found using the specified find criteria.");

            base.EnsureHandle(context);

            Handle.EnlistToken(new X509SecurityToken(targetCert));
        }
    }
}
