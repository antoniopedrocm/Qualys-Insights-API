using QualysInsights.Application.DTOs;
using QualysInsights.Application.Services;

namespace QualysInsights.UnitTests;

public sealed class BusinessClassifiersTests
{
    [Theory]
    [InlineData("DEV QA, Windows", "DEV_QA")]
    [InlineData("producao baixa", "PRD_Baixa")]
    [InlineData("PRD/ALTA", "PRD_Alta")]
    public void ClassifyWindow_RecognizesConfiguredWindows(string tags, string expected)
    {
        Assert.Equal(expected, BusinessClassifiers.ClassifyWindow(tags));
    }

    [Fact]
    public void IsDetectionFixed_UsesStatusValue()
    {
        Assert.True(BusinessClassifiers.IsDetectionFixed(new VulnerabilityDto { Status = "Fixed" }));
        Assert.False(BusinessClassifiers.IsDetectionFixed(new VulnerabilityDto { Status = "Active" }));
    }
}

