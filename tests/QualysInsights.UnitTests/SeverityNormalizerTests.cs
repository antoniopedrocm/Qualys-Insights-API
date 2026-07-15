using QualysInsights.Application.Services;

namespace QualysInsights.UnitTests;

public sealed class SeverityNormalizerTests
{
    [Fact]
    public void Normalize_ConvertsCommonQualysFormatsToPortuguese()
    {
        Assert.Equal("Crítica", SeverityNormalizer.Normalize("5"));
        Assert.Equal("Alta", SeverityNormalizer.Normalize("4 - High"));
        Assert.Equal("Média", SeverityNormalizer.Normalize("Medium"));
        Assert.Equal("Baixa", SeverityNormalizer.Normalize("baixa"));
        Assert.Equal("Info", SeverityNormalizer.Normalize("informational"));
    }
}

