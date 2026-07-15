using System.Net;
using System.Net.Http.Json;

namespace QualysInsights.IntegrationTests;

public sealed class ApiCompatibilityTests(QualysWebApplicationFactory factory) : IClassFixture<QualysWebApplicationFactory>
{
    [Fact]
    public async Task Health_ReturnsLegacyShape()
    {
        var client = factory.CreateClient();
        var response = await client.GetFromJsonAsync<Dictionary<string, object>>("/api/health");

        Assert.NotNull(response);
        Assert.Equal("online", response["status"].ToString());
        Assert.True(response.ContainsKey("hasCredentials"));
    }

    [Fact]
    public async Task MainEndpoints_ReturnExpectedContracts()
    {
        var client = factory.CreateClient();

        var hosts = await client.GetFromJsonAsync<ApiEnvelope>("/api/hosts");
        var vulns = await client.GetFromJsonAsync<ApiEnvelope>("/api/vulnerabilities");
        var scans = await client.GetFromJsonAsync<ApiEnvelope>("/api/scans");
        var dashboard = await client.GetFromJsonAsync<ApiEnvelope>("/api/dashboard/summary");

        Assert.True(hosts!.Success);
        Assert.True(vulns!.Success);
        Assert.True(scans!.Success);
        Assert.True(dashboard!.Success);
    }

    [Fact]
    public async Task Effectiveness_RequiresProtectionHeaderAndReturnsClassification()
    {
        var client = factory.CreateClient();

        var blocked = await client.PostAsJsonAsync("/api/effectiveness", new { detectionIds = new[] { "6385789118" } });
        Assert.Equal(HttpStatusCode.BadRequest, blocked.StatusCode);

        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/effectiveness")
        {
            Content = JsonContent.Create(new { detectionIds = new[] { "6385789118", "123", "abc" } })
        };
        request.Headers.Add("X-Requested-With", "QualysInsights");
        var response = await client.SendAsync(request);
        response.EnsureSuccessStatusCode();
        var payload = await response.Content.ReadFromJsonAsync<EffectivenessEnvelope>();

        Assert.Equal(3, payload!.Total);
        Assert.Equal(1, payload.Open);
        Assert.Equal(1, payload.Fixed);
        Assert.Equal(1, payload.Invalid);
    }

    [Fact]
    public async Task ExportCsv_DownloadsFile()
    {
        var client = factory.CreateClient();
        var response = await client.GetAsync("/api/export/vulnerabilities/csv");

        response.EnsureSuccessStatusCode();
        Assert.Equal("text/csv", response.Content.Headers.ContentType!.MediaType);
    }

    private sealed class ApiEnvelope
    {
        public bool Success { get; set; }
    }

    private sealed class EffectivenessEnvelope
    {
        public int Total { get; set; }
        public int Open { get; set; }
        public int Fixed { get; set; }
        public int Invalid { get; set; }
    }
}

