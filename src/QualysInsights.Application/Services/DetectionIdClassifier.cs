namespace QualysInsights.Application.Services;

public sealed record DetectionIdClassification(string DetectionId, string Status);

public sealed record DetectionIdClassificationResult(int Total, int Fixed, int Open, int Invalid, IReadOnlyList<DetectionIdClassification> Items);

public static class DetectionIdClassifier
{
    public static IReadOnlyList<string> Parse(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return Array.Empty<string>();
        }

        return input
            .Split(new[] { '\r', '\n', ',', ';', ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(token => !string.IsNullOrWhiteSpace(token))
            .Distinct(StringComparer.Ordinal)
            .ToArray();
    }

    public static DetectionIdClassificationResult Classify(IEnumerable<string> ids, ISet<string> activeSet)
    {
        var uniqueIds = ids
            .Select(id => id.Trim())
            .Where(id => id.Length > 0)
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        var items = uniqueIds.Select(id =>
        {
            if (!id.All(char.IsDigit))
            {
                return new DetectionIdClassification(id, "invalid");
            }

            return new DetectionIdClassification(id, activeSet.Contains(id) ? "open" : "fixed");
        }).ToArray();

        return new DetectionIdClassificationResult(
            items.Length,
            items.Count(item => item.Status == "fixed"),
            items.Count(item => item.Status == "open"),
            items.Count(item => item.Status == "invalid"),
            items);
    }
}

