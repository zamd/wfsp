using System;
using System.Activities;
using System.Activities.Expressions;
using System.ComponentModel;
using System.Drawing;
using System.IdentityModel.Tokens;
using System.Windows.Markup;
using Microsoft.Activities.SecurityPack.Designers;
using Microsoft.Activities.SecurityPack.ToolboxIcons;

namespace Microsoft.Activities.SecurityPack
{

    [Designer(typeof(InitializeActAsTokenDesigner))]
    [ToolboxBitmap(typeof(IconMoniker), "InitializeActAs")]
    [ContentProperty("Initializer")]
    public class InitializeActAsToken : NativeActivity
    {
        public InArgument<SecurityTokenHandle> TokenHandle { get; set; }
        public ActivityFunc<SecurityToken> Initializer { get; set; }

        protected override void CacheMetadata(NativeActivityMetadata metadata)
        {
            base.CacheMetadata(metadata);
            if (this.Initializer == null || this.Initializer.Handler == null)
            {
                metadata.AddValidationError(string.Format("The activity '{0}' must specify a token initializer.",
                     base.DisplayName));
            }
            else if ( !(this.Initializer.Handler is Activity<SecurityToken>) )
            {
                metadata.AddValidationError(string.Format("The activity '{0}' has an invalid token initializer. Please specify an intitializer of type {1}.",
                     base.DisplayName,"Activity<SecurityToken>"));  
            }
        }
        protected override void Execute(NativeActivityContext context)
        {
            context.ScheduleFunc<SecurityToken>(this.Initializer, OnCompleted);
        }

        void OnCompleted(NativeActivityContext context, ActivityInstance completedInstance, SecurityToken token)
        {
            // Try getting ambiant handle
            var handle = context.Properties.Find(SecurityTokenHandle.PropertyName) as SecurityTokenHandle;
            if (handle == null && this.TokenHandle != null)
                handle = this.TokenHandle.Get(context);
            
            if (handle == null)
                throw new InvalidOperationException(
                    string.Format("TokenHandle property must be set to a valid SecurityTokenHandle or '{0}' must be inside a TokenFlowScope activity.", this.DisplayName));

            // register ActAs Token with security handle
            //handle.ActAsToken = token;
            RegisterTokenWithHandle(handle, token);
        }
        protected virtual void RegisterTokenWithHandle(SecurityTokenHandle handle, SecurityToken token)
        {
             handle.ActAsToken = token;
        }
    }

    public class InitializeFlowToken : InitializeActAsToken
    {
        protected override void RegisterTokenWithHandle(SecurityTokenHandle handle, SecurityToken token)
        {
            handle.EnlistedTokens.Add(token);
        }
    }

    //
    internal sealed class InitializeActAsTokenInOperationContext : NativeActivity
    {
        public InArgument<SecurityTokenHandle> TokenHandle { get; set; }
        public ActivityFunc<SecurityToken> Initializer { get; set; }

        private ActivityFunc<SecurityToken> _internalInitializer;
        private readonly DelegateOutArgument<SecurityToken> tokenDelegate = new DelegateOutArgument<SecurityToken>("tokenDelegate");

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

            //wraps the original intializer inside a WCF OperationContext. This will ensure that intializers always have access to OperationContext.
            // Some intializers might fetch ActAs token from WCF SecurityContext.
            this._internalInitializer = new ActivityFunc<SecurityToken>
            {
                Handler = new OperationContextScope
                {
                    Body = new InvokeFunc<SecurityToken>
                    {
                        Func = this.Initializer,
                        Result = new OutArgument<SecurityToken>(tokenDelegate)
                    }
                },
                Result = tokenDelegate
            };

            metadata.AddImplementationDelegate(this._internalInitializer);
        }
        protected override void Execute(NativeActivityContext context)
        {
            context.ScheduleFunc<SecurityToken>(this._internalInitializer, OnCompleted);
        }

        void OnCompleted(NativeActivityContext context, ActivityInstance completedInstance, SecurityToken token)
        {
            // Try getting ambiant handle
            var handle = context.Properties.Find(SecurityTokenHandle.PropertyName) as SecurityTokenHandle;
            if (handle == null)
                handle = this.TokenHandle.Get(context);
            // register ActAs Token with security handle
            handle.ActAsToken = token;
        }
    }
}
