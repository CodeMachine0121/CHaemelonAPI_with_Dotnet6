using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace CHameleonHashApi_for_CSharp;

public interface SignatureInterface
{
    public BigInteger Signing(string msg);
    public bool Verifying(string msg, BigInteger r, ECPoint PublicKey);
}