using System.Text;
using QualysInsights.Application.DTOs;
using QualysInsights.Infrastructure.Export;

namespace QualysInsights.UnitTests;

public sealed class ExportServiceTests
{
    [Fact]
    public void BuildVulnerabilitiesCsv_ProtectsFormulaInjection()
    {
        var service = new SpreadsheetExportService();
        var csv = Encoding.UTF8.GetString(service.BuildVulnerabilitiesCsv([
            new VulnerabilityDto
            {
                DetectionId = "1",
                HostDns = "=cmd",
                Title = "+title",
                Solution = "-solution",
                Results = "@result"
            }
        ]));

        Assert.Contains("\"'=cmd\"", csv);
        Assert.Contains("\"'+title\"", csv);
        Assert.Contains("\"'-solution\"", csv);
        Assert.Contains("\"'@result\"", csv);
    }

    [Fact]
    public void BuildVulnerabilitiesWorkbook_CreatesWorkbookBytes()
    {
        var service = new SpreadsheetExportService();
        var bytes = service.BuildVulnerabilitiesWorkbook([new VulnerabilityDto { DetectionId = "1", Title = "Sample" }]);

        Assert.True(bytes.Length > 0);
    }
}

