using QualysInsights.Application.Services;

namespace QualysInsights.UnitTests;

public sealed class DetectionIdClassifierTests
{
    [Fact]
    public void Parse_AcceptsMultipleSeparatorsAndRemovesDuplicates()
    {
        var parsed = DetectionIdClassifier.Parse("123\n456,789;123  999\t789");

        Assert.Equal(["123", "456", "789", "999"], parsed);
    }

    [Fact]
    public void Classify_MarksOpenFixedAndInvalid()
    {
        var result = DetectionIdClassifier.Classify(["100", "200", "abc", "300", "100"], new HashSet<string>(["200", "300"]));

        Assert.Equal(4, result.Total);
        Assert.Equal(2, result.Open);
        Assert.Equal(1, result.Fixed);
        Assert.Equal(1, result.Invalid);
        Assert.Equal("fixed", result.Items[0].Status);
        Assert.Equal("open", result.Items[1].Status);
        Assert.Equal("invalid", result.Items[2].Status);
    }
}

