using QualysInsights.Infrastructure.Qualys;

namespace QualysInsights.UnitTests;

public sealed class QualysXmlParserTests
{
    private readonly QualysXmlParser _parser = new();

    [Fact]
    public void ParseHosts_ExtractsHostsAndNormalizesTags()
    {
        var hosts = _parser.ParseHosts(ReadFixture("hosts.xml"));

        var host = Assert.Single(hosts);
        Assert.Equal("10.0.0.1", host.Ip);
        Assert.Equal("DEV_QA, Windows_Server", host.Tags);
    }

    [Fact]
    public void ParseVulnerabilities_ExtractsOpenAndFixedDetections()
    {
        var vulns = _parser.ParseVulnerabilities(ReadFixture("vulnerabilities.xml"));

        Assert.Equal(2, vulns.Count);
        Assert.Equal("6385789118", vulns[0].DetectionId);
        Assert.Equal("Confirmed", vulns[0].TypeDetected);
        Assert.False(vulns[0].IsFixed);
        Assert.True(vulns[1].IsFixed);
    }

    [Fact]
    public void ParseScans_ExtractsScanState()
    {
        var scan = Assert.Single(_parser.ParseScans(ReadFixture("scans.xml")));

        Assert.Equal("scan/123", scan.Ref);
        Assert.Equal("Finished", scan.State);
    }

    [Fact]
    public void ParseKnowledgeBase_ExtractsTitleAndSolution()
    {
        var kb = _parser.ParseKnowledgeBase(ReadFixture("kb.xml"));

        Assert.Equal("KB Title", kb["100001"].Title);
        Assert.Equal("KB Solution", kb["100001"].Solution);
    }

    [Fact]
    public void ParseQueueError_DetectsCode1960AndRetryAfter()
    {
        var queue = _parser.ParseQueueError(ReadFixture("queue.xml"));

        Assert.NotNull(queue);
        Assert.Equal("1960", queue.Code);
        Assert.Equal(2, queue.CallsToFinish);
        Assert.Equal(60, queue.RetryAfterSeconds);
    }

    private static string ReadFixture(string fileName)
    {
        return File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", fileName));
    }
}

