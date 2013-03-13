using System;
using System.Collections.ObjectModel;
using System.IdentityModel.Policy;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Security;
using System.Xml;

namespace Microsoft.Activities.SecurityPack
{
    /// <summary>
    /// Enables the serialization of GenericXmlSecurityToken.
    /// </summary>
    class GenericXmlSecurityTokenHandler : SecurityTokenHandler
    {
        static string[] _tokenTypeIdentifiers = new string[] { "http://microsoft.activities.wfsp/genericxml" };
        static string xmlns = "urn:microsoft.activities.wfsp";
        const string TokenId = "BufferedGenericXmlSecurityToken";

        public override string[] GetTokenTypeIdentifiers()
        {
            return _tokenTypeIdentifiers;
        }

        public override Type TokenType
        {
            get { return typeof(BufferedGenericXmlSecurityToken); }
        }

        public override void WriteToken(XmlWriter writer, SecurityToken token)
        {
            var targetToken = token as BufferedGenericXmlSecurityToken;
            if (targetToken == null)
            {
                throw new InvalidOperationException("GenericXmlSecurityTokenHandler can only write BufferedGenericXmlSecurityToken tokens.");
            }

            writer.WriteStartElement(TokenId, xmlns);
            writer.WriteAttributeString("trustVersion", xmlns, targetToken.TrustVersion.ToString());

            if (targetToken.TrustVersion == WSTrustVersion.WSTrustFeb2005)
            {
                new WSTrustFeb2005RequestSerializer().WriteXml(targetToken.Rst, writer, new WSTrustSerializationContext());
                new WSTrustFeb2005ResponseSerializer().WriteXml(targetToken.Rstr, writer, new WSTrustSerializationContext());
            }
            else
            {
                new WSTrust13RequestSerializer().WriteXml(targetToken.Rst, writer, new WSTrustSerializationContext());
                new WSTrust13ResponseSerializer().WriteXml(targetToken.Rstr, writer, new WSTrustSerializationContext());
            }

            writer.WriteEndElement();
        }
        public override SecurityToken ReadToken(XmlReader reader)
        {
            RequestSecurityToken rst;
            RequestSecurityTokenResponse rstr;

            reader.MoveToContent();

            var strTrustVersion = reader.GetAttribute("trustVersion", xmlns);
            var trustVersion = (WSTrustVersion)Enum.Parse(typeof(WSTrustVersion),strTrustVersion);

            reader.ReadStartElement(TokenId, xmlns);

            if (trustVersion == WSTrustVersion.WSTrustFeb2005)
            {
                rst = new WSTrustFeb2005RequestSerializer().ReadXml(reader, new WSTrustSerializationContext());
                rstr = new WSTrustFeb2005ResponseSerializer().ReadXml(reader, new WSTrustSerializationContext());
            }
            else
            {
                rst = new WSTrust13RequestSerializer().ReadXml(reader, new WSTrustSerializationContext());
                rstr = new WSTrust13ResponseSerializer().ReadXml(reader, new WSTrustSerializationContext());
            }

            reader.ReadEndElement();

            return BufferedGenericXmlSecurityToken.Create(rst, rstr, trustVersion);
        }

        public override bool CanReadToken(XmlReader reader)
        {
            return reader.IsStartElement(TokenId, xmlns);
        }
        public override bool CanWriteToken
        {
            get
            {
                return true;
            }
        }
        public override bool CanValidateToken
        {
            get
            {
                return false;
            }
        }
    }

    /// <summary>
    /// GenericXmlSecurityToken is not serializable out of box. BufferedGenericXmlSecurityToken makes it serializable by storing all constituents of GenericXmlSecurityToken.
    /// </summary>
    class BufferedGenericXmlSecurityToken : GenericXmlSecurityToken
    {
        public RequestSecurityToken Rst { get; set; }
        public RequestSecurityTokenResponse Rstr { get; set; }
        public WSTrustVersion TrustVersion { get; set; }

        BufferedGenericXmlSecurityToken(
            RequestSecurityToken rst, RequestSecurityTokenResponse rstr, WSTrustVersion trustVersion,
            XmlElement tokenXml, SecurityToken proofToken, DateTime effectiveTime, DateTime expirationTime, SecurityKeyIdentifierClause internalTokenReference, SecurityKeyIdentifierClause externalTokenReference, ReadOnlyCollection<IAuthorizationPolicy> authorizationPolicies)
            : base(tokenXml, proofToken, effectiveTime, expirationTime, internalTokenReference, externalTokenReference, authorizationPolicies)
        {
            this.Rst = rst;
            this.Rstr = rstr;
            this.TrustVersion = trustVersion;
        }
        /// <summary>
        /// Creates a GenericXmlSecurityToken and stores the raw input parameters for serialization and future token creations.
        /// </summary>
        /// <param name="rst"></param>
        /// <param name="rstr"></param>
        /// <param name="trustVersion"></param>
        /// <returns>A derived of GenericXmlSecurityToken</returns>
        public static BufferedGenericXmlSecurityToken Create(RequestSecurityToken rst, RequestSecurityTokenResponse rstr, WSTrustVersion trustVersion)
        {
            // Create token using WIF
            var nullFactory = new WSTrustChannelFactory(new CustomBinding(new HttpTransportBindingElement()));

            if (trustVersion == WSTrustVersion.WSTrustFeb2005)
                nullFactory.TrustVersion = System.ServiceModel.Security.TrustVersion.WSTrustFeb2005;
            else
                nullFactory.TrustVersion = System.ServiceModel.Security.TrustVersion.WSTrust13;

            var trustChannel = (WSTrustChannel)nullFactory.CreateChannel(new EndpointAddress("http://null-Endpoint"));
            var token = trustChannel.GetTokenFromResponse(rst, rstr) as GenericXmlSecurityToken;

            return new BufferedGenericXmlSecurityToken(
                rst, rstr, trustVersion,
                token.TokenXml, token.ProofToken, token.ValidFrom, token.ValidTo, token.InternalTokenReference, token.ExternalTokenReference, token.AuthorizationPolicies);
        }
    }
}
