using System;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Linq;
using System.ServiceModel;
using System.ServiceModel.Configuration;
using System.ServiceModel.Description;
using System.ServiceModel.Dispatcher;
using System.ServiceModel.Security.Tokens;

namespace Microsoft.Activities.SecurityPack
{
    class WorkflowClientCredentials : ClientCredentials, IEndpointBehavior
    {
        public ClientCredentials Orignal { get; private set; }

        public void AddBindingParameters(ServiceEndpoint endpoint, System.ServiceModel.Channels.BindingParameterCollection bindingParameters)
        {
            Orignal = bindingParameters.Find<ClientCredentials>();
            if (Orignal != null)
                bindingParameters.Remove(Orignal);
            else Orignal = new ClientCredentials(); // Create & use a default ClientCredentials as none of the configured BindingElements has created one.

            bindingParameters.Add(this);
        }

        public override void ApplyClientBehavior(ServiceEndpoint serviceEndpoint, ClientRuntime behavior) { }

        public void ApplyDispatchBehavior(ServiceEndpoint endpoint, EndpointDispatcher endpointDispatcher) { }

        public void Validate(ServiceEndpoint endpoint) { }

        public override SecurityTokenManager CreateSecurityTokenManager()
        {
            return new WorkflowSecurityTokenManager(Orignal);
        }

        protected override ClientCredentials CloneCore()
        {
            return new WorkflowClientCredentials() { Orignal = this.Orignal.Clone() };
        }
    }
    class WorkflowSecurityTokenManager : ClientCredentialsSecurityTokenManager
    {
        ClientCredentials orignalCredentials;

        public WorkflowSecurityTokenManager(ClientCredentials parent)
            : base(parent)
        {
            this.orignalCredentials = parent;
        }
        public override SecurityTokenProvider CreateSecurityTokenProvider(SecurityTokenRequirement tokenRequirement)
        {
            return new GenericSecurityTokenProvider(tokenRequirement, orignalCredentials);
        }
    }

    class GenericSecurityTokenProvider : SecurityTokenProvider
    {
        SecurityTokenRequirement tokenRequirement;
        ClientCredentials orignal;
        public GenericSecurityTokenProvider(SecurityTokenRequirement tokenRequirement, ClientCredentials orignal)
        {
            this.tokenRequirement = tokenRequirement;
            this.orignal = orignal;

        }

        bool IsIssuedSecurityTokenRequirement(SecurityTokenRequirement requirement)
        {
            return ((requirement != null) && requirement.Properties.ContainsKey(ServiceModelSecurityTokenRequirement.IssuerAddressProperty));
        }

        protected override System.IdentityModel.Tokens.SecurityToken GetTokenCore(TimeSpan timeout)
        {
            var requirement = tokenRequirement as InitiatorServiceModelSecurityTokenRequirement;
            var tokenType = requirement.TokenType;
            if (tokenType == null && IsIssuedSecurityTokenRequirement(requirement))
                tokenType = SecurityTokenTypes.Saml;

            SecurityToken token = null;

            if (OperationContext.Current != null &&
                OperationContext.Current.Extensions.Find<TokensExtension>() != null)
                token = OperationContext.Current.Extensions.Find<TokensExtension>().FindToken(tokenType);

            Exception exception = null;
            if (token == null && orignal != null)
            {
                try
                {
                    //TODO: fix timeout calculation.
                    var provider = orignal.CreateSecurityTokenManager().CreateSecurityTokenProvider(requirement);

                    if (provider is ICommunicationObject)
                        ((ICommunicationObject)provider).Open(timeout);
                    token = provider.GetToken(timeout);
                }
                catch (Exception exp)
                {
                    exception = exp;
                }
            }

            if (token == null)
                throw new InvalidOperationException(
                    string.Format("Failed to create a {0} token. " +
                    "Please make sure you have correctly configured ClientCredentials or WorkflowClientCredenails. "
                    + "See inner exception for more details.",
                    tokenType.Split('/').Last()), exception);

            return token;
        }
    }

    /// <summary>
    ///     Represents a configuration element that configures client credentials to be used in workflow data model. 
    /// </summary>
    public class WorkflowClientCredentialsBehaviorElement : BehaviorExtensionElement
    {
        public override Type BehaviorType
        {
            get { return typeof(WorkflowClientCredentials); }
        }

        protected override object CreateBehavior()
        {
            return new WorkflowClientCredentials();
        }
    }
}
