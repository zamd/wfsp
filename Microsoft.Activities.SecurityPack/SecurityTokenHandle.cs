using System;
using System.Activities;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Xml;
using System.Xml.Schema;
using System.Xml.Serialization;

namespace Microsoft.Activities.SecurityPack
{
    /// <summary>
    /// Represents a handle to store tokens
    /// </summary>
    /* SecurityTokenHandle is the only object exposed to workflow data model and all the tokens simply hangs off this handle. 
     * This design provides a level indirection for the serialization and deserialization of tokens currently enlisted with this handle.
     * SecurityTokenHandle implements the IXmlSerializable and serializes the enlisted tokens using their WS-Security wire representation. 
     * */
    public class SecurityTokenHandle : Handle, IXmlSerializable
    {
        const string LocalName = "securityTokenHandle";
        const string Xmlns = "urn:microsoft.activities.wfsp";
        const string ActAsLabel = "actAsToken";
        private readonly List<SecurityToken> _enlistedTokens = new List<SecurityToken>();

        public static readonly string PropertyName = typeof(SecurityTokenHandle).FullName;
        public ICollection<SecurityToken> EnlistedTokens
        {
            get
            {
                return _enlistedTokens;
            }
        }
        public SecurityToken ActAsToken { get; set; }


        public void EnlistToken(SecurityToken token)
        {
            _enlistedTokens.Add(token);
        }
        #region IXmlSerializable
        public XmlSchema GetSchema()
        {
            throw new NotImplementedException();
        }

        public void ReadXml(XmlReader reader)
        {
            if (reader.ReadToDescendant(LocalName, Xmlns))
            {
                reader.ReadStartElement(LocalName, Xmlns);
                DeSerializeTokens(reader);
                reader.ReadEndElement();
            }
        }

        public void WriteXml(XmlWriter writer)
        {
            writer.WriteStartElement(LocalName, Xmlns);
            SerializeTokens(writer);
            writer.WriteEndElement();
        }
        #endregion

        private void DeSerializeTokens(XmlReader reader)
        {
            while (SecurityTokenHandlerCollection.CanReadToken(reader))
            {
                var token = SecurityTokenHandlerCollection.ReadToken(reader);
                _enlistedTokens.Add(token);
            }

            //Look for & read ActAs token.
            if (reader.IsStartElement(ActAsLabel, Xmlns))
            {
                reader.ReadStartElement();
                ActAsToken = SecurityTokenHandlerCollection.ReadToken(reader);
                reader.ReadEndElement();
            }
        }

        private void SerializeTokens(XmlWriter writer)
        {
            //Write flow tokens.
            foreach (var token in _enlistedTokens)
            {
                SecurityTokenHandlerCollection.WriteToken(writer, token);
            }
            //Write ActAs token
            if (ActAsToken != null)
            {
                writer.WriteStartElement(ActAsLabel, Xmlns);
                SecurityTokenHandlerCollection.WriteToken(writer, ActAsToken);
                writer.WriteEndElement();
            }
        }
        private SecurityTokenHandlerCollection _handlerCol;
        private SecurityTokenHandlerCollection SecurityTokenHandlerCollection
        {
            get
            {
                if (_handlerCol == null)
                {
                    _handlerCol = SecurityTokenHandlerCollection.CreateDefaultSecurityTokenHandlerCollection();
                    //Add custom handler for our SAML token container.
                    _handlerCol.AddOrReplace(new GenericXmlSecurityTokenHandler());
                }
                return _handlerCol;
            }
        }
    }
}
