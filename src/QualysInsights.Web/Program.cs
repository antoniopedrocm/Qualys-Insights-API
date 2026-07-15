using System.Text.Json;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using QualysInsights.Application.Interfaces;
using QualysInsights.Application.Options;
using QualysInsights.Application.Services;
using QualysInsights.Infrastructure;
using QualysInsights.Infrastructure.Persistence;
using QualysInsights.Web.Security;
using QualysInsights.Web.Middleware;
using QualysInsights.Web.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddControllers()
    .AddJsonOptions(options =>
    {
        options.JsonSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
        options.JsonSerializerOptions.DictionaryKeyPolicy = null;
    });

builder.Services.AddProblemDetails();
builder.Services.AddMemoryCache();
builder.Services.AddHttpContextAccessor();

builder.Services.AddConfiguredOptions(builder.Configuration);
builder.Services.AddScoped<IQualysDataService, QualysDataService>();
builder.Services.AddQualysInfrastructure();
builder.Services.AddHostedService<QualysRefreshBackgroundService>();

var authOptions = builder.Configuration.GetSection(AppAuthenticationOptions.SectionName).Get<AppAuthenticationOptions>() ?? new();
if (authOptions.Mode.Equals("Windows", StringComparison.OrdinalIgnoreCase))
{
    builder.Services
        .AddAuthentication(NegotiateDefaults.AuthenticationScheme)
        .AddNegotiate();
}
else if (authOptions.Mode.Equals("ApiKey", StringComparison.OrdinalIgnoreCase))
{
    builder.Services
        .AddAuthentication(ApiKeyAuthenticationHandler.SchemeName)
        .AddScheme<ApiKeyAuthenticationSchemeOptions, ApiKeyAuthenticationHandler>(ApiKeyAuthenticationHandler.SchemeName, _ => { });
}

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("QualysInsightsAccess", policy =>
    {
        if (authOptions.Mode.Equals("Disabled", StringComparison.OrdinalIgnoreCase))
        {
            policy.RequireAssertion(_ => true);
            return;
        }

        policy.RequireAuthenticatedUser();
        policy.RequireAssertion(context => IsGroupAllowed(context, authOptions.AllowedActiveDirectoryGroups));
    });
});

builder.Services.AddRateLimiter(options =>
{
    var rateOptions = builder.Configuration.GetSection(RateLimitOptions.SectionName).Get<RateLimitOptions>() ?? new();
    options.AddPolicy("heavy", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: context.User.Identity?.Name ?? context.Connection.RemoteIpAddress?.ToString() ?? "anonymous",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = rateOptions.PermitLimit,
                Window = TimeSpan.FromSeconds(rateOptions.WindowSeconds),
                QueueLimit = 0,
                AutoReplenishment = true
            }));
});

var corsOptions = builder.Configuration.GetSection(CorsPolicyOptions.SectionName).Get<CorsPolicyOptions>() ?? new();
if (corsOptions.AllowedOrigins.Count > 0)
{
    builder.Services.AddCors(options =>
    {
        options.AddPolicy("ConfiguredCors", policy =>
            policy.WithOrigins(corsOptions.AllowedOrigins.ToArray())
                .AllowAnyHeader()
                .AllowAnyMethod()
                .AllowCredentials());
    });
}

var hostingOptions = builder.Configuration.GetSection(HostingOptions.SectionName).Get<HostingOptions>() ?? new();
builder.WebHost.ConfigureKestrel(options => options.Limits.MaxRequestBodySize = hostingOptions.MaxRequestBodyBytes);
builder.Services.Configure<IISServerOptions>(options => options.MaxRequestBodySize = hostingOptions.MaxRequestBodyBytes);

var app = builder.Build();

var pathBase = app.Services.GetRequiredService<Microsoft.Extensions.Options.IOptions<HostingOptions>>().Value.PathBase;
if (!string.IsNullOrWhiteSpace(pathBase))
{
    app.UsePathBase(pathBase);
}

await InitializePersistenceAsync(app);

app.UseMiddleware<CorrelationIdMiddleware>();
app.UseMiddleware<ExceptionHandlingMiddleware>();
app.UseMiddleware<SecurityHeadersMiddleware>();
app.UseMiddleware<UnsafeMethodHeaderMiddleware>();

if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
}

if (corsOptions.AllowedOrigins.Count > 0)
{
    app.UseCors("ConfiguredCors");
}

app.UseDefaultFiles();
app.UseStaticFiles();
app.UseRouting();
app.UseRateLimiter();

if (!authOptions.Mode.Equals("Disabled", StringComparison.OrdinalIgnoreCase))
{
    app.UseAuthentication();
}

app.UseAuthorization();
app.MapControllers();
app.MapFallbackToFile("index.html");

app.Run();

static bool IsGroupAllowed(AuthorizationHandlerContext context, IReadOnlyList<string> allowedGroups)
{
    if (allowedGroups.Count == 0)
    {
        return true;
    }

    return allowedGroups.Any(group =>
        context.User.IsInRole(group)
        || context.User.Claims.Any(claim => string.Equals(claim.Value, group, StringComparison.OrdinalIgnoreCase)));
}

static async Task InitializePersistenceAsync(WebApplication app)
{
    using var scope = app.Services.CreateScope();
    var dbContext = scope.ServiceProvider.GetRequiredService<QualysInsightsDbContext>();
    await dbContext.Database.MigrateAsync();
    await scope.ServiceProvider.GetRequiredService<ILegacyEffectivenessCacheMigrator>().MigrateIfEnabledAsync(CancellationToken.None);
}

public partial class Program;

