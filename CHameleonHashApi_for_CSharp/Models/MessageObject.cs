using CHameleonHashApi_for_CSharp;

namespace ECC_Practice.Models;

public class MessageObject
{
    public string message { get; set; }
    public string signature { get; set; }
    
    public PointObject publicKey { get; set; }
    
}