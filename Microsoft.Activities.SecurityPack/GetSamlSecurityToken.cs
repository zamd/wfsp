using System;
using System.Activities;
using System.Activities.Statements;
using System.ComponentModel;
using System.Drawing;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.ServiceModel;
using System.ServiceModel.Activities;
using System.ServiceModel.Channels;
using Microsoft.Activities.SecurityPack.Designers;
using Microsoft.Activities.SecurityPack.ToolboxIcons;

namespace Microsoft.Activities.SecurityPack
{
    [Designer(typeof(GetSamlSecurityTokenDesigner))]
    [ToolboxBitmap(typeof(IconMoniker), "GetSamlToken")]
    public sealed class GetSamlSecurityToken : Activity<SecurityToken>
    {
        public GetSamlSecurityToken()
        {
            base.Implementation = delegate
            {
                var rstr = new Variable<Message>("rstr");
                var rst = new Variable<RequestSecurityToken>("rst");
                var samlToken = new Variable<SecurityToken>("samlToken");

                var rstSend = new Send
                {
                    ServiceContractName = "IWSTrustContract",
                    OperationName = "Issue",
                    Content = SendContent.Create(new InArgument<Message>(
                        new CreateRSTMessage()
                        {
                            MessageVersion = new InArgument<MessageVersion>(new MessageVersionValue { VersionFlag = this.MessageVersion }),
                            AppliesTo = new InArgument<Uri>(context => this.AppliesTo.Get(context)),
                            RST = new OutArgument<RequestSecurityToken>(rst)
                        }
                        )),
                    Endpoint = IssuerEndpoint,
                    EndpointAddress = IssuerEndpointAddress,
                    EndpointConfigurationName = IssuerEndpointConfigurationName
                };


                return new CorrelationScope
                {
                    Body = new Sequence
                    {
                        Variables = { rstr, rst, samlToken },
                        Activities =
                        {
                            rstSend,
                            new ReceiveReply{ Request = rstSend, Content = ReceiveContent.Create(new OutArgument<Message>(rstr))},
                            new CreateToken{ RST = rst, RSTR=rstr, Result = new OutArgument<SecurityToken>(samlToken)},
                            new Assign<SecurityToken>
                            { 
                                To = new OutArgument<SecurityToken>(context=>this.Result.Get(context)),
                                Value = samlToken
                            }
                        }
                    }
                };
            };

        }

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

        protected override void CacheMetadata(ActivityMetadata metadata)
        {
            base.CacheMetadata(metadata);

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
        }
    }
}
