using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace CHameleonHashApi_for_CSharp;

public class ChameleonHash : SignatureInterface
{
    private BigInteger kn;
    public BigInteger? sessionKey;
    public ECPoint P, Kn ,CH;
    
    public ChameleonHash(ECPoint P, BigInteger kn, ECPoint Kn)
    {
        this.kn = kn;
        this.kn = kn;
        this.P = P;
    }
    
    // SHA256 運算
    private BigInteger Hash(String msg)
    {
        byte[] bmsg = Encoding.ASCII.GetBytes(msg);
        Sha256Digest sha256Digest = new Sha256Digest();
        sha256Digest.BlockUpdate(bmsg, 0, bmsg.Length);
        byte[] hash = new byte[sha256Digest.GetDigestSize()];
        sha256Digest.DoFinal(hash, 0);
        return new BigInteger(hash);
    }

    // 設置 Session
    public void setSessionkey(ECPoint rP)
    {
        this.sessionKey = rP.Multiply(this.kn).Normalize().XCoord.ToBigInteger();
        
        // calculate Chameleon Hash
        BigInteger msgHash = Hash("Helloworld");
        var dn = msgHash.Multiply(this.kn).Multiply(new BigInteger(BitConverter.GetBytes(-1)));
        var rn = this.sessionKey.Add(dn);
        this.CH = this.Kn.Multiply(msgHash).Add(P.Multiply(rn)).Normalize();
        Console.WriteLine("[+] SK: "+dn.ToString());
        Console.WriteLine("[+] CH: "+CH.XCoord.ToString()+" , "+CH.YCoord.ToString());
    }

  
    public BigInteger Signing(string msg)
    {
        BigInteger msgHash = Hash(msg);
        var dn = msgHash.Multiply(this.kn).Multiply(new BigInteger(BitConverter.GetBytes(-1)));
        var rn = this.sessionKey.Add(dn);
        return rn;
    }

    public bool Verifying(string msg, BigInteger r, ECPoint PublicKey)
    {
        var msgHash = Hash(msg);
        var CH = PublicKey.Multiply(msgHash).Add(P.Multiply(r)).Normalize();
        if (CH.Equals(this.CH))
            return true;
        return false;
    }
}