using System.Security;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace ECC_Practice;

class AesKeyIV
{
    public Byte[] Key = new Byte[16];
    public Byte[] IV = new Byte[16];
    public AesKeyIV(string strKey)
    {
        var sha = new Sha256Digest();
        var hash = new byte[sha.GetDigestSize()];
        var data = Encoding.ASCII.GetBytes(strKey);
        sha.BlockUpdate(data, 0, data.Length);
        sha.DoFinal(hash, 0);
        Array.Copy(hash, 0, Key, 0, 16);
        Array.Copy(hash, 16, IV, 0, 16);
    }
}

public class AESCipher
{
    public static string Encryption(string msg, string Key)
    {
        Console.WriteLine("[+] Encryption Phase");
        var keyIv = new AesKeyIV(Key);
        var cipher = CipherUtilities.GetCipher("AES/CBC/PKCS7");
        cipher.Init(true, new ParametersWithIV(new KeyParameter(keyIv.Key), keyIv.IV));
        var rawData = Encoding.UTF8.GetBytes(msg);

        var cipherText = Convert.ToBase64String(cipher.DoFinal(rawData));
        Console.WriteLine("\t[-] CipherText: "+cipherText);
        return cipherText;
    }

    public static string Decryption(string enMsg, string key)
    {
        Console.WriteLine("[+] Decryption Phase");
        var keyIv = new AesKeyIV(key);
        var cipher = CipherUtilities.GetCipher("AES/CBC/PKCS7");
        cipher.Init(false, new ParametersWithIV(new KeyParameter(keyIv.Key), keyIv.IV));
        var encData = Convert.FromBase64String(enMsg);
        
        var plainText= Encoding.UTF8.GetString(cipher.DoFinal(encData));
        Console.WriteLine("\t[-] PlainText: "+plainText);
        return plainText;
    }
}