namespace Paseto.Extensions;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Paseto.Cryptography.Key;
using static Paseto.Utils.EncodingHelper;

internal static class ByteArrayExtensions
{
    public static RsaPrivateCrtKeyParameters ToPrivateKeyFromByteArray(this byte[] buffer)
    {
        var xmlString = GetString(buffer);

        var xmlDoc = new XmlDocument();
        xmlDoc.LoadXml(xmlString);

        BigInteger modulus = null;
        BigInteger exponent = null;
        BigInteger p = null;
        BigInteger q = null;
        BigInteger dP = null;
        BigInteger dQ = null;
        BigInteger qInv = null;
        BigInteger d = null;
        if (xmlDoc.DocumentElement!.Name.Equals("RSAKeyValue"))
        {
            foreach (XmlNode node in xmlDoc.DocumentElement.ChildNodes)
            {
                switch (node.Name)
                {
                    case "Modulus": modulus = string.IsNullOrEmpty(node.InnerText) ? null : ConvertToBigInteger(node.InnerText); break;
                    case "Exponent": exponent = string.IsNullOrEmpty(node.InnerText) ? null : ConvertToBigInteger(node.InnerText); break;
                    case "P": p = string.IsNullOrEmpty(node.InnerText) ? null : ConvertToBigInteger(node.InnerText); break;
                    case "Q": q = string.IsNullOrEmpty(node.InnerText) ? null : ConvertToBigInteger(node.InnerText); break;
                    case "DP": dP = string.IsNullOrEmpty(node.InnerText) ? null : ConvertToBigInteger(node.InnerText); break;
                    case "DQ": dQ = string.IsNullOrEmpty(node.InnerText) ? null : ConvertToBigInteger(node.InnerText); break;
                    case "InverseQ": qInv = string.IsNullOrEmpty(node.InnerText) ? null : ConvertToBigInteger(node.InnerText); break;
                    case "D": d = string.IsNullOrEmpty(node.InnerText) ? null : ConvertToBigInteger(node.InnerText); break;
                }
            }
        }
        else
        {
            throw new PasetoInvalidException("Invalid XML RSA key.");
        }

        return new RsaPrivateCrtKeyParameters(modulus, exponent, d, p, q, dP, dQ, qInv);
    }

    public static RsaKeyParameters ToPublicKeyFromByteArray(this byte[] buffer)
    {
        var xmlString = GetString(buffer);

        var xmlDoc = new XmlDocument();
        xmlDoc.LoadXml(xmlString);

        BigInteger modulus = null;
        BigInteger exponent = null;
        if (xmlDoc.DocumentElement!.Name.Equals("RSAKeyValue"))
        {
            foreach (XmlNode node in xmlDoc.DocumentElement.ChildNodes)
            {
                switch (node.Name)
                {
                    case "Modulus": modulus = string.IsNullOrEmpty(node.InnerText) ? null : ConvertToBigInteger(node.InnerText); break;
                    case "Exponent": exponent = string.IsNullOrEmpty(node.InnerText) ? null : ConvertToBigInteger(node.InnerText); break;
                }
            }
        }
        else
        {
            throw new PasetoInvalidException("Invalid XML RSA key.");
        }

        return new RsaKeyParameters(false, modulus, exponent);
    }

    private static BigInteger ConvertToBigInteger(string value) => new(1, Convert.FromBase64String(value));
}
