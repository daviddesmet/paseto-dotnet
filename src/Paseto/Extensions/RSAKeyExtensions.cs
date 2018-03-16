namespace Paseto.Extensions
{
    using System;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Xml;
    using System.Xml.Linq;

    using Newtonsoft.Json;

    public static class RSAKeyExtensions
    {
        #region JSON

        public static void FromJsonString(this RSA rsa, string jsonString)
        {
            if (string.IsNullOrWhiteSpace(jsonString))
                throw new ArgumentNullException(nameof(jsonString));

            try
            {
                var paramsJson = JsonConvert.DeserializeObject<RSAParametersJson>(jsonString);

                var parameters = new RSAParameters()
                {
                    Modulus = paramsJson.Modulus != null ? Convert.FromBase64String(paramsJson.Modulus) : null,
                    Exponent = paramsJson.Exponent != null ? Convert.FromBase64String(paramsJson.Exponent) : null,
                    P = paramsJson.P != null ? Convert.FromBase64String(paramsJson.P) : null,
                    Q = paramsJson.Q != null ? Convert.FromBase64String(paramsJson.Q) : null,
                    DP = paramsJson.DP != null ? Convert.FromBase64String(paramsJson.DP) : null,
                    DQ = paramsJson.DQ != null ? Convert.FromBase64String(paramsJson.DQ) : null,
                    InverseQ = paramsJson.InverseQ != null ? Convert.FromBase64String(paramsJson.InverseQ) : null,
                    D = paramsJson.D != null ? Convert.FromBase64String(paramsJson.D) : null
                };
                
                rsa.ImportParameters(parameters);
            }
            catch
            {
                throw new Exception("Invalid JSON RSA key.");
            }
        }

        public static string ToJsonString(this RSA rsa, bool includePrivateParameters)
        {
            RSAParameters parameters = rsa.ExportParameters(includePrivateParameters);

            var parasJson = new RSAParametersJson()
            {
                Modulus = parameters.Modulus != null ? Convert.ToBase64String(parameters.Modulus) : null,
                Exponent = parameters.Exponent != null ? Convert.ToBase64String(parameters.Exponent) : null,
                P = parameters.P != null ? Convert.ToBase64String(parameters.P) : null,
                Q = parameters.Q != null ? Convert.ToBase64String(parameters.Q) : null,
                DP = parameters.DP != null ? Convert.ToBase64String(parameters.DP) : null,
                DQ = parameters.DQ != null ? Convert.ToBase64String(parameters.DQ) : null,
                InverseQ = parameters.InverseQ != null ? Convert.ToBase64String(parameters.InverseQ) : null,
                D = parameters.D != null ? Convert.ToBase64String(parameters.D) : null
            };

            return JsonConvert.SerializeObject(parasJson);
        }

        #endregion

        #region XML

        public static void FromCompatibleXmlString(this RSA rsa, string xmlString)
        {
            if (string.IsNullOrWhiteSpace(xmlString))
                throw new ArgumentNullException(nameof(xmlString));

            var parameters = new RSAParameters();

            var xmlDoc = new XmlDocument();
            xmlDoc.LoadXml(xmlString);

            if (xmlDoc.DocumentElement.Name.Equals("RSAKeyValue"))
            {
                foreach (XmlNode node in xmlDoc.DocumentElement.ChildNodes)
                {
                    switch (node.Name)
                    {
                        case "Modulus": parameters.Modulus = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "Exponent": parameters.Exponent = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "P": parameters.P = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "Q": parameters.Q = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "DP": parameters.DP = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "DQ": parameters.DQ = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "InverseQ": parameters.InverseQ = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "D": parameters.D = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                    }
                }
            }
            else
            {
                throw new Exception("Invalid XML RSA key.");
            }

            rsa.ImportParameters(parameters);
        }

        public static string ToCompatibleXmlString(this RSA rsa, bool includePrivateParameters, SaveOptions options = SaveOptions.DisableFormatting)
        {
            var parameters = rsa.ExportParameters(includePrivateParameters);

            var xml = string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent><P>{2}</P><Q>{3}</Q><DP>{4}</DP><DQ>{5}</DQ><InverseQ>{6}</InverseQ><D>{7}</D></RSAKeyValue>",
                  parameters.Modulus != null ? Convert.ToBase64String(parameters.Modulus) : null,
                  parameters.Exponent != null ? Convert.ToBase64String(parameters.Exponent) : null,
                  parameters.P != null ? Convert.ToBase64String(parameters.P) : null,
                  parameters.Q != null ? Convert.ToBase64String(parameters.Q) : null,
                  parameters.DP != null ? Convert.ToBase64String(parameters.DP) : null,
                  parameters.DQ != null ? Convert.ToBase64String(parameters.DQ) : null,
                  parameters.InverseQ != null ? Convert.ToBase64String(parameters.InverseQ) : null,
                  parameters.D != null ? Convert.ToBase64String(parameters.D) : null);

            var doc = XElement.Parse(xml);
            doc.Descendants().Where(e => string.IsNullOrEmpty(e.Value)).Remove();

            return doc.ToString(options);
        }

        #endregion

        internal class RSAParametersJson
        {
            public string Modulus { get; set; }

            public string Exponent { get; set; }

            [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
            public string P { get; set; }

            [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
            public string Q { get; set; }

            [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
            public string DP { get; set; }

            [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
            public string DQ { get; set; }

            [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
            public string InverseQ { get; set; }

            [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
            public string D { get; set; }
        }
    }
}
