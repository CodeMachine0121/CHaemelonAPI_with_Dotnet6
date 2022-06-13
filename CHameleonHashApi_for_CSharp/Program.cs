using CHameleonHashApi_for_CSharp;
using ECC_Practice;
using ECC_Practice.Models;
using Newtonsoft.Json;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();
var keypair = new KeyGenerator(256);
//ECPoint P, BigInteger kn
var chameleon =new ChameleonHash(keypair.publicKey.Parameters.G, keypair.getPrivateKey(), keypair.getPublicKey());



// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.MapGet("/publicKey", async () =>
{
    var x = keypair.publicKey.Q.XCoord.ToString();
    var y = keypair.publicKey.Q.YCoord.ToString();
    return Results.Ok(new{x=x,y=y});
});
app.MapPost("/sessionKey", async (HttpRequest request) =>
{
    // receive msg
    StreamReader streamReader = new StreamReader(request.Body);
    var jsonData = await streamReader.ReadToEndAsync();
    var point = JsonConvert.DeserializeObject<PointObject>(jsonData.ToString());
    
    // create ECC point object
    var publickey = keypair.getPublicKey();
    var bx = new BigInteger(point.x, 16);
    var by = new BigInteger(point.y, 16);
    ECPoint ecpoint = publickey.Curve.CreatePoint(bx,by).Normalize();
    
    // set Session key
    Console.WriteLine($"[+] Received publicKey: x: {ecpoint.XCoord.ToString()}, y:{ecpoint.YCoord.ToString()}");
    chameleon.setSessionkey(ecpoint);
    return Results.Ok("OK");
});

app.MapPost("/dataReqeust", async (HttpRequest request) =>
{
    // receive msg
    StreamReader streamReader = new StreamReader(request.Body);
    var jsonData = await streamReader.ReadToEndAsync();
    var receivedMessage = JsonConvert.DeserializeObject<MessageObject>(jsonData.ToString());
    
    // Verify
    var publicKey = keypair.getPublicKey().Curve.CreatePoint(
        new BigInteger(receivedMessage.publicKey.x,16),
        new BigInteger(receivedMessage.publicKey.y,16)
    );
    var result = chameleon.Verifying(receivedMessage.message, new BigInteger(receivedMessage.signature, 16), publicKey);
    if (!result)
        return Results.Unauthorized();
    // send Message back and sign it
    var msgBack = "This is data you want";
    var order = keypair.getPublicKey().Curve.Order;
    var r = chameleon.Signing(msgBack, order).ToString(16);
    var publicObj = new PointObject(){x=keypair.getPublicKey().XCoord.ToString(), y = keypair.getPublicKey().YCoord.ToString()};
    return Results.Ok(new MessageObject(){message = msgBack, signature = r, publicKey = publicObj});
});

app.UseHttpsRedirection();
app.Run();

