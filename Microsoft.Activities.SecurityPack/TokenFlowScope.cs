using System;
using System.Activities;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Runtime.Serialization;
using System.ServiceModel;
using System.ServiceModel.Activities;
using System.ServiceModel.Security.Tokens;
using System.Windows.Markup;
using Microsoft.Activities.SecurityPack.Designers;
using Microsoft.Activities.SecurityPack.ToolboxIcons;

namespace Microsoft.Activities.SecurityPack
{
    /// <summary>
    /// Enables token flow from WF data model to WCF security layer. 
    /// </summary>
    [Designer(typeof(TokenFlowScopeDesigner))]
    [ToolboxBitmap(typeof(IconMoniker), "TokenFlowScope")]
    [ContentProperty("Body")]
    public class TokenFlowScope : NativeActivity
    {
        public InArgument<SecurityTokenHandle> TokenHandle { get; set; }
        public Activity Body { get; set; }

        protected override void CacheMetadata(NativeActivityMetadata metadata)
        {
            var runtimeArg = new RuntimeArgument("TokenHandle", typeof(SecurityTokenHandle), ArgumentDirection.In);

            metadata.Bind(TokenHandle, runtimeArg);
            metadata.AddArgument(runtimeArg);
            metadata.AddChild(this.Body);
        }

        protected override void Execute(NativeActivityContext context)
        {
            if (this.Body != null)
            {
                var handle = context.Properties.Find(SecurityTokenHandle.PropertyName) as SecurityTokenHandle;
                if (handle == null && this.TokenHandle != null)
                    handle = this.TokenHandle.Get(context);    // Set ambiant handle

                if (handle == null)
                    throw new InvalidOperationException(
                        string.Format("TokenHandle property must be set to a valid SecurityTokenHandle or '{0}' must be inside a TokenFlowScope activity.", this.DisplayName));

                
                context.Properties.Add(SecurityTokenHandle.PropertyName, handle);
                context.Properties.Add("TokenFlowHandler", new TokenFlowHandler(handle));
                context.ScheduleActivity(this.Body);
            }
        }

        [DataContract]
        class TokenFlowHandler : ISendMessageCallback
        {
            [DataMember]
            SecurityTokenHandle _tokenHandle;
            public TokenFlowHandler(SecurityTokenHandle tokenHandle)
            {
                this._tokenHandle = tokenHandle;
            }

            public void OnSendMessage(OperationContext operationContext)
            {
                //TODO: message properties
                operationContext.Extensions.Add(new TokensExtension(_tokenHandle.EnlistedTokens));
            }
        }
    }

    public class TokensExtension : IExtension<OperationContext>
    {
        ICollection<SecurityToken> tokens;
        public TokensExtension(ICollection<SecurityToken> tokens)
        {
            this.tokens = tokens;
        }

        public ICollection<SecurityToken> Tokens
        {
            get
            {
                return this.tokens;
            }
        }

        public void Attach(OperationContext owner) { }
        public void Detach(OperationContext owner) { }

        public SecurityToken FindToken(string tokenType)
        {
            if (tokenType == SecurityTokenTypes.UserName)
                return tokens.OfType<UserNameSecurityToken>().FirstOrDefault();

            if (tokenType == SecurityTokenTypes.Kerberos)
                return tokens.OfType<WindowsSecurityToken>().FirstOrDefault();

            if (tokenType == SecurityTokenTypes.Saml)
                return tokens.OfType<GenericXmlSecurityToken>().FirstOrDefault();

            if (tokenType == SecurityTokenTypes.X509Certificate)
                return tokens.OfType<X509SecurityToken>().FirstOrDefault();

            if (tokenType == ServiceModelSecurityTokenTypes.SspiCredential)
                return tokens.OfType<SspiSecurityToken>().FirstOrDefault();

            return null;
        }
    }
}
