using System.Globalization;
using System.Text;

namespace QualysInsights.Application.Services;

public static class SeverityNormalizer
{
    private static readonly Dictionary<string, string> SeverityMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["5"] = "Crítica",
        ["4"] = "Alta",
        ["3"] = "Média",
        ["2"] = "Baixa",
        ["1"] = "Info",
        ["critical"] = "Crítica",
        ["high"] = "Alta",
        ["medium"] = "Média",
        ["low"] = "Baixa",
        ["info"] = "Info",
        ["informational"] = "Info"
    };

    public static string Normalize(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return "Info";
        }

        var raw = input.Trim();
        if (SeverityMap.TryGetValue(raw, out var mapped))
        {
            return mapped;
        }

        var digit = raw.FirstOrDefault(c => c is >= '1' and <= '5');
        if (digit != default && SeverityMap.TryGetValue(digit.ToString(), out mapped))
        {
            return mapped;
        }

        var accentless = StripAccents(raw).ToLowerInvariant();
        if (accentless.Contains("crit", StringComparison.Ordinal)) return "Crítica";
        if (accentless.Contains("high", StringComparison.Ordinal) || accentless.Contains("alta", StringComparison.Ordinal)) return "Alta";
        if (accentless.Contains("med", StringComparison.Ordinal)) return "Média";
        if (accentless.Contains("low", StringComparison.Ordinal) || accentless.Contains("baixa", StringComparison.Ordinal)) return "Baixa";

        return "Info";
    }

    public static string StripAccents(string value)
    {
        var normalized = value.Normalize(NormalizationForm.FormD);
        var builder = new StringBuilder(normalized.Length);

        foreach (var c in normalized)
        {
            if (CharUnicodeInfo.GetUnicodeCategory(c) != UnicodeCategory.NonSpacingMark)
            {
                builder.Append(c);
            }
        }

        return builder.ToString().Normalize(NormalizationForm.FormC);
    }
}

