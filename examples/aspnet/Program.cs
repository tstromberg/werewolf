var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions
{
    Args = args,
    ContentRootPath = AppContext.BaseDirectory,
});
builder.WebHost.UseUrls("http://0.0.0.0:8080");

var app = builder.Build();
app.MapGet("/", () => "Hello from ASP.NET Core on werewolf!\n");
app.MapGet("/health", () => "ok\n");
app.Run();
