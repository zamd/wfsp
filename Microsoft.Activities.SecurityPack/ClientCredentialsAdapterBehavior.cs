using System;
using System.Configuration;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Configuration;
using System.ServiceModel.Description;
using System.ServiceModel.Dispatcher;

namespace Microsoft.Activities.SecurityPack
{
    /// <summary>
    ///This configuration element extends the clientCredentials element by adding support for specifying UserName/Password clientCredential from configuration file.
    /// </summary>
    public class ClientCredentialsAdapterBehaviorElement : BehaviorExtensionElement
    {
        ConfigurationPropertyCollection _properties;

        [ConfigurationProperty("userName")]
        public UserNameElement UserName
        {
            get
            {
                return (UserNameElement)base["userName"];
            }
        }

        protected override ConfigurationPropertyCollection Properties
        {
            get
            {
                if (this._properties == null)
                {
                    var props = new ConfigurationPropertyCollection
                                    {new ConfigurationProperty("userName", typeof (UserNameElement))};

                    this._properties = props;
                }
                return this._properties;
            }
        }


        public override Type BehaviorType
        {
            get { return typeof(ClientCredentialsAdapterBehavior); }
        }

        protected override object CreateBehavior()
        {
            return new ClientCredentialsAdapterBehavior(this);
        }

    }
    /// <summary>
    /// Encapsulate the configuration representation of userName client credential
    /// </summary>
    public class UserNameElement : ConfigurationElement
    {
        ConfigurationPropertyCollection _properties;

        [ConfigurationProperty("userName")]
        public string UserName
        {
            get
            {
                return (string)base["userName"];
            }
        }
        [ConfigurationProperty("password")]
        public string Password
        {
            get
            {
                return (string)base["password"];
            }
        }

        protected override ConfigurationPropertyCollection Properties
        {
            get
            {
                if (this._properties == null)
                {
                    var props = new ConfigurationPropertyCollection();
                    props.Add(new ConfigurationProperty("userName", typeof(string)));
                    props.Add(new ConfigurationProperty("password", typeof(string)));

                    this._properties = props;
                }
                return this._properties;
            }

        }
    }
    /// <summary>
    /// Enables specification of userName clientCredential in the configuration. This behavior should only be used with encrypted credential Section.
    /// </summary>
    class ClientCredentialsAdapterBehavior : IEndpointBehavior
    {
        readonly ClientCredentialsAdapterBehaviorElement configElement;

        public ClientCredentialsAdapterBehavior(ClientCredentialsAdapterBehaviorElement configElement)
        {
            this.configElement = configElement;
        }

        public void AddBindingParameters(ServiceEndpoint endpoint, BindingParameterCollection bindingParameters){}

        public void ApplyClientBehavior(ServiceEndpoint endpoint, System.ServiceModel.Dispatcher.ClientRuntime clientRuntime)
        {
            var clientCredentials = endpoint.Behaviors.Find<ClientCredentials>();
            Adapt(clientCredentials);

            clientRuntime.MessageInspectors.Add(new ClientMsg());
        }

        public void ApplyDispatchBehavior(ServiceEndpoint endpoint, EndpointDispatcher endpointDispatcher) { }

        public void Validate(ServiceEndpoint endpoint){}

        void Adapt(ClientCredentials orignalCredentials)
        {
            orignalCredentials.UserName.UserName = configElement.UserName.UserName;
            orignalCredentials.UserName.Password = configElement.UserName.Password;
        }
    }

    class ClientMsg : IClientMessageInspector
    {
        #region IClientMessageInspector Members

        public void AfterReceiveReply(ref System.ServiceModel.Channels.Message reply, object correlationState)
        {

        }

        public object BeforeSendRequest(ref System.ServiceModel.Channels.Message request, IClientChannel channel)
        {
            var oc = OperationContext.Current;
            return null;
        }

        #endregion
    }

}
