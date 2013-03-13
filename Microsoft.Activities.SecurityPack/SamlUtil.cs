using System;
using System.Activities;
using System.Activities.Statements;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.ServiceModel;
using System.ServiceModel.Activities;
using System.ServiceModel.Channels;
using System.ServiceModel.Security;


namespace Microsoft.Activities.SecurityPack
{

    public enum WSTrustVersion
    {
        WSTrustFeb2005,
        WSTrust13
    }
    public enum SoapAddressingVersion
    {
        Default,
        None,
        Soap11,
        Soap11WSAddressing10,
        Soap11WSAddressingAugust2004,
        Soap12,
        Soap12WSAddressing10,
        Soap12WSAddressingAugust2004
    };

    internal class CreateRSTMessage : CodeActivity<Message>
    {
        public InArgument<Uri> AppliesTo { get; set; }
        public InArgument<MessageVersion> MessageVersion { get; set; }

        public OutArgument<RequestSecurityToken> RST { get; set; }

        public WSTrustVersion TrustVersion { get; set; }

        protected override Message Execute(CodeActivityContext context)
        {
            string requestType, action;
            WSTrustRequestSerializer requestSerializer;

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

            var version = this.MessageVersion.Get(context);

            var rst = new RequestSecurityToken(requestType);
            rst.AppliesTo = new EndpointReference(AppliesTo.Get(context).AbsoluteUri);
            RST.Set(context, rst);
            return Message.CreateMessage(version, action, new WSTrustRequestBodyWriter(rst,
                requestSerializer, new WSTrustSerializationContext()));
        }
    }

    internal class MessageVersionValue : CodeActivity<MessageVersion>
    {
        public InArgument<SoapAddressingVersion> VersionFlag { get; set; }

        protected override MessageVersion Execute(CodeActivityContext context)
        {
            return Converter.ToMessageVersion(this.VersionFlag.Get(context));
        }
    }

    internal class CreateToken : CodeActivity<SecurityToken>
    {
        public InArgument<Message> RSTR { get; set; }
        public InArgument<RequestSecurityToken> RST { get; set; }

        public WSTrustVersion TrustVersion { get; set; }

        protected override SecurityToken Execute(CodeActivityContext context)
        {
            RequestSecurityTokenResponse rstr = null;

            var rst = this.RST.Get(context);
            var message = this.RSTR.Get(context);

            if (TrustVersion == WSTrustVersion.WSTrustFeb2005)
                rstr = new WSTrustFeb2005ResponseSerializer().ReadXml(message.GetReaderAtBodyContents(), new WSTrustSerializationContext());
            else
                rstr = new WSTrust13ResponseSerializer().ReadXml(message.GetReaderAtBodyContents(), new WSTrustSerializationContext());

            context.Track(new AcquiredSamlTokenRecord(rstr.AppliesTo.Uri, rstr.Lifetime.Expires));
            return BufferedGenericXmlSecurityToken.Create(rst, rstr, TrustVersion);
        }
    }
    
    internal class EnlistToken : CodeActivity
    {
        public InArgument<SecurityTokenHandle> TokenHandle { get; set; }
        public InArgument<SecurityToken> Token { get; set; }
        protected override void Execute(CodeActivityContext context)
        {
            var handle = this.TokenHandle.Get(context);
            handle.EnlistToken(this.Token.Get(context));
        }
    }

    internal class IssueRequestReply : Activity<Message>
    {
        public InArgument<Message> RST { get; set; }
        public InArgument<Uri> IssuerEndpointAddress { get; set; }

        public Endpoint IssuerEndpoint { get; set; }
        public string IssuerEndpointConfigurationName { get; set; }

        public IssueRequestReply()
        {
            base.Implementation = delegate
            {
                var rstr = new Variable<Message>("rstr");

                var rstSend = new Send
                {
                    ServiceContractName = "IWSTrustContract",
                    OperationName = "Issue",
                    Content = SendContent.Create(new InArgument<Message>(context => this.RST.Get(context))),
                    Endpoint = IssuerEndpoint,
                    EndpointAddress = new InArgument<Uri>(context => this.IssuerEndpointAddress.Get(context)),
                    EndpointConfigurationName = IssuerEndpointConfigurationName
                };

                return new CorrelationScope
                {
                    Body = new Sequence
                    {
                        Variables = { rstr },
                        Activities =
                        {
                            rstSend,
                            new ReceiveReply{ Request = rstSend, Content = ReceiveContent.Create(new OutArgument<Message>(rstr))},
                            new Assign<Message>
                            { 
                                To = new OutArgument<Message>(context=>this.Result.Get(context)), 
                                Value = rstr
                            }
                        }
                    }
                };

            };

        }
    }

    internal static class Converter
    {
        public static MessageVersion ToMessageVersion(SoapAddressingVersion versionFlag)
        {
            switch (versionFlag)
            {
                case SoapAddressingVersion.Default:
                    return MessageVersion.Default;
                case SoapAddressingVersion.None:
                    return MessageVersion.None;
                case SoapAddressingVersion.Soap11:
                    return MessageVersion.Soap11;
                case SoapAddressingVersion.Soap11WSAddressing10:
                    return MessageVersion.Soap11WSAddressing10;
                case SoapAddressingVersion.Soap11WSAddressingAugust2004:
                    return MessageVersion.Soap11WSAddressingAugust2004;
                case SoapAddressingVersion.Soap12:
                    return MessageVersion.Soap12;
                case SoapAddressingVersion.Soap12WSAddressing10:
                    return MessageVersion.Soap12WSAddressing10;
                case SoapAddressingVersion.Soap12WSAddressingAugust2004:
                    return MessageVersion.Soap12WSAddressingAugust2004;
                default:
                    return MessageVersion.Default;
            }
        }
    }
}
