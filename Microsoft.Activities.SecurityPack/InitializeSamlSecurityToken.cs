using System;
using System.Activities;
using System.ComponentModel;
using System.Drawing;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Security;
using Microsoft.Activities.SecurityPack.Designers;
using Microsoft.Activities.SecurityPack.ToolboxIcons;


namespace Microsoft.Activities.SecurityPack
{
    [Designer(typeof(InitializeSamlSecurityTokenDesigner))]
    [ToolboxBitmap(typeof(IconMoniker),"InitializeSamlToken")]
    public sealed class InitializeSamlSecurityToken : NativeActivity
    {
        private IssueRequestReply _issueRequestReply;
        private Variable<Message> _rstMessageVariable;
        private Variable<RequestSecurityToken> _rstVariable;

        [DefaultValue((string)null)]
        [TypeConverterAttribute(typeof(ExpandableObjectConverter))]
        public Endpoint IssuerEndpoint { get; set; }

        [DefaultValue((string)null)]
        public InArgument<Uri> IssuerEndpointAddress { get; set; }

        [DefaultValue((string)null)]
        public InArgument<Uri> AppliesTo { get; set; }

        [DefaultValue((string)null)]
        public string IssuerEndpointConfigurationName { get; set; }

        [DefaultValue(WSTrustVersion.WSTrustFeb2005)]
        public WSTrustVersion TrustVersion { get; set; }

        [DefaultValue(SoapAddressingVersion.Default)]
        public SoapAddressingVersion MessageVersion { get; set; }

        public InArgument<SecurityTokenHandle> TokenHandle { get; set; }

        protected override void CacheMetadata(NativeActivityMetadata metadata)
        {
            base.CacheMetadata(metadata);

            #region "validation"
            if (this.IssuerEndpoint == null)
            {
                if (string.IsNullOrEmpty(this.IssuerEndpointConfigurationName))
                {
                    metadata.AddValidationError(string.Format("The activity '{0}' must specify either the IssuerEndpoint or IssuerEndpointConfigurationName property.",
                        base.DisplayName));
                }
            }
            else
            {
                if (!string.IsNullOrEmpty(this.IssuerEndpointConfigurationName))
                {
                    metadata.AddValidationError(string.Format("Both the IssuerEndpoint and the IssuerEndpointConfigurationName properties are set in activity '{0}'. However, only one can be set at a time.",
                    base.DisplayName));
                }
                if (this.IssuerEndpoint.Binding == null)
                {
                    metadata.AddValidationError(string.Format("IssuerEndpoint with Name='{0}' has no Binding. Please provide a Binding to this Endpoint.",
                        this.IssuerEndpoint.Name));
                }
            }

            if (this.AppliesTo == null)
            {
                metadata.AddValidationError(string.Format("The activity '{0}' must specify AppliesTo property.",
                    base.DisplayName));
            }
            #endregion

            _rstMessageVariable = new Variable<Message>("rstMessage");
            _rstVariable = new Variable<RequestSecurityToken>("rst");
            metadata.AddImplementationVariable(_rstMessageVariable);
            metadata.AddImplementationVariable(_rstVariable);

            _issueRequestReply = new IssueRequestReply
            {
                IssuerEndpoint = this.IssuerEndpoint,
                IssuerEndpointConfigurationName = this.IssuerEndpointConfigurationName,
                RST = new InArgument<Message>(context => _rstMessageVariable.Get(context)),
                IssuerEndpointAddress = new InArgument<Uri>(context => IssuerEndpointAddress.Get(context))
            };
            metadata.AddImplementationChild(_issueRequestReply);
        }

        protected override void Execute(NativeActivityContext context)
        {
            string requestType, action;
            WSTrustRequestSerializer requestSerializer;
            var serializationContext = new WSTrustSerializationContext();

            if (TrustVersion == WSTrustVersion.WSTrustFeb2005)
            {
                requestType = WSTrustFeb2005Constants.RequestTypes.Issue;
                action = WSTrustFeb2005Constants.Actions.Issue;
                requestSerializer = new WSTrustFeb2005RequestSerializer();
            }
            else
            {
                requestType = WSTrust13Constants.RequestTypes.Issue;
                action = WSTrust13Constants.Actions.Issue;
                requestSerializer = new WSTrust13RequestSerializer();
            }

            var version = Converter.ToMessageVersion(this.MessageVersion);

            var rst = new RequestSecurityToken(requestType);
            
            var handle = EnsureTokenHandle(context);
            if (handle.ActAsToken != null)
                rst.ActAs = new SecurityTokenElement(handle.ActAsToken);

            rst.AppliesTo = new EndpointReference(AppliesTo.Get(context).AbsoluteUri);

            _rstVariable.Set(context, rst);
            _rstMessageVariable.Set(context,
                Message.CreateMessage(version, action, (BodyWriter)new WSTrustRequestBodyWriter(rst, requestSerializer, serializationContext)));

            context.ScheduleActivity<Message>(_issueRequestReply, OnCompleted);
        }
        void OnCompleted(NativeActivityContext context, ActivityInstance completedInstance, Message result)
        {
            if (result.IsFault)
                throw new FaultException(MessageFault.CreateFault(result, 20 * 1024));//TODO: Fix size calculation.

            var rst = this._rstVariable.Get(context);
            RequestSecurityTokenResponse rstr = null;

            if (TrustVersion== WSTrustVersion.WSTrustFeb2005)
                rstr = new WSTrustFeb2005ResponseSerializer().ReadXml(result.GetReaderAtBodyContents(), new WSTrustSerializationContext());            
            else
                rstr = new WSTrust13ResponseSerializer().ReadXml(result.GetReaderAtBodyContents(), new WSTrustSerializationContext());            
            
            var token = BufferedGenericXmlSecurityToken.Create(rst, rstr, TrustVersion);
                
            var handle = EnsureTokenHandle(context);

            handle.EnlistToken(token);

            context.Track(new AcquiredSamlTokenRecord(rstr.AppliesTo.Uri, rstr.Lifetime.Expires));
        }

        private SecurityTokenHandle EnsureTokenHandle(NativeActivityContext context)
        {
            // Try getting ambiant handle
            var handle = context.Properties.Find(SecurityTokenHandle.PropertyName) as SecurityTokenHandle;
            if (handle == null && this.TokenHandle != null)
                handle = this.TokenHandle.Get(context);

            if (handle == null)
                throw new InvalidOperationException(
                    string.Format("TokenHandle property must be set to a valid SecurityTokenHandle or '{0}' must be inside a TokenFlowScope activity.", this.DisplayName));

            return handle;
        }
    }
}
