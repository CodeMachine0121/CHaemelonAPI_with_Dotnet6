using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using BigInteger = Org.BouncyCastle.Math.BigInteger;
using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;
namespace CHameleonHashApi_for_CSharp;


public class KeyGenerator
{
    public int keysize;

    private AsymmetricCipherKeyPair keypair;
    public ECPublicKeyParameters publicKey;
    private ECPrivateKeyParameters privateKey;
    
    public KeyGenerator(int keysize)
    {
        this.keysize = keysize;
        this.keypair = generateKeys(keysize); // 產生金鑰對
        this.publicKey = (ECPublicKeyParameters) this.keypair.Public; // 產生公鑰物件
        this.privateKey = (ECPrivateKeyParameters) this.keypair.Private; // 產生私鑰物件
    }
    private AsymmetricCipherKeyPair generateKeys(int keySize)
    {
        var gen = new ECKeyPairGenerator("ECDSA");
        //  隨機亂數
        var secureRandom = new SecureRandom();
        // 創立ECC參數物件
        var keyGenParam = new KeyGenerationParameters(secureRandom, keySize);
        gen.Init(keyGenParam);
        return gen.GenerateKeyPair();
    }
    


    public BigInteger getPrivateKey()
    {
        return this.privateKey.D;
    }
    public ECPoint getPublicKey()
    {
        return this.publicKey.Q;
    }

    // 輸出ECC相關資訊
    private static void GenerateKey_by_Curve(int keysize)
    {
        var keygen = new KeyGenerator(256);
        var keypair = keygen.generateKeys(keysize);


        // 寫成 pem格式
        TextWriter textWriter = new StringWriter();
        PemWriter pemWriter = new PemWriter(textWriter);
        pemWriter.WriteObject(keypair.Private);
        pemWriter.Writer.Flush();
        string? privateKey = textWriter.ToString();
        Console.WriteLine("[+] Private Key in pem Format:\n " + privateKey);
        textWriter = new StringWriter();
        pemWriter = new PemWriter(textWriter);
        pemWriter.WriteObject(keypair.Public);
        pemWriter.Writer.Flush();
        string? publicKey = textWriter.ToString();
        Console.WriteLine("[+] Public key in pem Format: \n" + publicKey);
        // 輸出各項參數
        var privateParameter = (ECPrivateKeyParameters)keypair.Private;
        var privateKeyValue = privateParameter.D.ToString(16);
        Console.WriteLine("[+] Private Key Value: " + privateKeyValue);

        var publicParameter = (ECPublicKeyParameters)keypair.Public;
        var publicX = publicParameter.Q.XCoord.ToString();
        var publicY = publicParameter.Q.YCoord.ToString();
        Console.WriteLine("[+] Public Key X-value: " + publicX);
        Console.WriteLine("[+] Public Key Y-value: " + publicY);

        var Px = privateParameter.Parameters.G.XCoord.ToString();
        var Py = privateParameter.Parameters.G.YCoord.ToString();
        Console.WriteLine("[+] Px: " + Px);
        Console.WriteLine("[+] Py: " + Py);
    }

    /*
    public static void Debug()
    {
        
        // Alice
        Console.WriteLine("[+] Alice's Phase##################################################");
        var keygen = new KeyGenerator(256);
        var keypair = keygen.generateKeys(256);
       
        // random * P
        var alicePrivateKey = (ECPrivateKeyParameters)keypair.Private;
       
        
        //Console.WriteLine("[+] rpX: "+Alice_rp.XCoord.ToString());
        //Console.WriteLine("[+] rpY: "+Alice_rp.YCoord.ToString());
        
        // Bob
        Console.WriteLine("[+] Bob's Phase##################################################");
        var bobkeygen = new KeyGenerator(256);
        var bobkeypair = bobkeygen.generateKeys(256);
        BigInteger bobRandom = keygen.getBigRandomInteger(256);
        // random *P
        var bobPrivateKey = (ECPrivateKeyParameters) bobkeypair.Private;
        var bobRp = bobPrivateKey.Parameters.G.Multiply(bobRandom);
        //Console.WriteLine("[+] rpX: "+Bob_rp.XCoord.ToString());
        //Console.WriteLine("[+] rpY: "+Bob_rp.YCoord.ToString());
        
        // Remember to Normalize the Point!
        // Alice receive Bob's rp
        var aliceSessionKey =bobRp.Multiply(aliceRandom).Normalize();
        // Bob receive Alice's rp
        var bobSessionKey = aliceRp.Multiply(bobRandom).Normalize();
        
        Console.WriteLine("[+] Random Number: ");
        Console.WriteLine("\t[-]Alice r: "+aliceRandom.ToString(16));
        Console.WriteLine("\t[-]Bob   r: "+bobRandom.ToString(16));

        
        Console.WriteLine("[+] Session Key Comparation: ");
        bool result = aliceSessionKey.XCoord.ToString().Equals(bobSessionKey.XCoord.ToString());
        Console.WriteLine("\t[-] Alice : \n\t  x: "+ aliceSessionKey.XCoord.ToString()+"\n\t  y: "+aliceSessionKey.YCoord.ToString());
        Console.WriteLine("\t[-] Bob   : \n\t  x: "+bobSessionKey.XCoord.ToString()+" \n\t  y: "+bobSessionKey.YCoord.ToString());
        Console.WriteLine("\t[-]Result: "+result);
    }*/
}