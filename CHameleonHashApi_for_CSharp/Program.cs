using CHameleonHashApi_for_CSharp;
using Newtonsoft.Json;

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
    StreamReader streamReader = new StreamReader(request.Body);
    var jsonData = await streamReader.ReadToEndAsync();
    var point = JsonConvert.DeserializeObject<PointObject>(jsonData.ToString());
    var x = point.x;
    var y = point.y;
    return Results.Ok(new {x=x,y=y});
});
app.UseHttpsRedirection();
app.Run();

