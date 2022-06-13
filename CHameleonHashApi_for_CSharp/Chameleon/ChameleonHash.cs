using System.Text;
using CHameleonHashApi_for_CSharp;
using Org.BouncyCastle.Crypto.Digests;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;


namespace ECC_Practice;

public class ChameleonHash : SignatureInterface
{
    private BigInteger kn;
    public BigInteger? sessionKey;
    public ECPoint P, CH, Kn;
    
    public ChameleonHash(ECPoint P, BigInteger kn, ECPoint Kn)
    {
        this.kn = kn; // private key
        this.Kn = Kn; // public key
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
        Console.WriteLine("[+] setSessionkey Phase: ");
        this.sessionKey = rP.Multiply(this.kn).Normalize().XCoord.ToBigInteger();
        // calculate Chameleon Hash
        BigInteger msgHash = Hash("Helloworld");
        var dn = msgHash.Multiply(this.kn).Multiply(new BigInteger(BitConverter.GetBytes(-1)));
        var rn = this.sessionKey.Add(dn);
        this.CH = this.Kn.Multiply(msgHash).Add(P.Multiply(rn)).Normalize();
        Console.WriteLine("\t[-] SK: "+this.sessionKey.ToString(16));
        Console.WriteLine("\t[-] CH: "+CH.XCoord.ToString()+" , "+CH.YCoord.ToString());
    }

  
    public BigInteger Signing(string msg, BigInteger order)
    {
        Console.WriteLine("[+] Chamemelon Hash Signing Phase: ");
        BigInteger msgHash = Hash(msg);
        var dn = msgHash.Multiply(this.kn).Multiply(new BigInteger(BitConverter.GetBytes(-1)));
        var rn = this.sessionKey.Add(dn).Mod(order);
        Console.WriteLine($"\t[-] Message: {msg}");
        Console.WriteLine($"\t[-] Signature: {rn.ToString(16)}");
        return rn;
    }

    public bool Verifying(string msg, BigInteger r, ECPoint PublicKey)
    {
        Console.WriteLine("[+] Chameleon Hash Verify Phase: ");
        var msgHash = Hash(msg);
        var CH = PublicKey.Multiply(msgHash).Add(P.Multiply(r)).Normalize();
        var result = CH.Equals(this.CH);
        Console.WriteLine($"\t[-] Verify Result: {result}");
        return result;
    }
    
}