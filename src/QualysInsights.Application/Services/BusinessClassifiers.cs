using System.Text.RegularExpressions;
using QualysInsights.Application.DTOs;

namespace QualysInsights.Application.Services;

public static class BusinessClassifiers
{
    public static readonly string[] DetectionWindows = ["DEV_QA", "PRD_Baixa", "PRD_Alta"];

    public static readonly IReadOnlyDictionary<string, string> DetectionWindowLabels = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["DEV_QA"] = "Desenvolvimento e Qualidade",
        ["PRD_Baixa"] = "Produção Baixa",
        ["PRD_Alta"] = "Produção Alta"
    };

    private static readonly IReadOnlyDictionary<string, string[]> DetectionWindowTagMatchers = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
    {
        ["DEV_QA"] = ["DEV_QA", "DESENVOLVIMENTO_E_QUALIDADE", "DESENVOLVIMENTO", "QUALIDADE"],
        ["PRD_Baixa"] = ["PRD_BAIXA", "PRODUCAO_BAIXA", "PRODUÇÃO_BAIXA"],
        ["PRD_Alta"] = ["PRD_ALTA", "PRODUCAO_ALTA", "PRODUÇÃO_ALTA"]
    };

    public static IReadOnlyList<string> ParseHostTags(object? hostTags)
    {
        if (hostTags is null)
        {
            return Array.Empty<string>();
        }

        if (hostTags is IEnumerable<string> tags)
        {
            return tags.Where(tag => !string.IsNullOrWhiteSpace(tag)).Select(tag => tag.Trim()).ToArray();
        }

        return hostTags.ToString()!
            .Split(new[] { ',', ';', '|' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(tag => !string.IsNullOrWhiteSpace(tag))
            .ToArray();
    }

    public static string NormalizeTagString(string? tags)
    {
        return Regex.Replace(tags ?? "", @"\s+", "_").Replace("/", "_", StringComparison.Ordinal).ToUpperInvariant();
    }

    public static string? ClassifyWindow(string? hostTags)
    {
        var normalized = NormalizeTagString(hostTags);
        foreach (var window in DetectionWindows)
        {
            if (DetectionWindowTagMatchers[window].Any(tag => normalized.Contains(tag, StringComparison.OrdinalIgnoreCase)))
            {
                return window;
            }
        }

        return null;
    }

    public static string GetDetectionStatusValue(VulnerabilityDto item)
    {
        var candidates = new[] { item.Status, item.State, item.DetectionStatus, item.FindingStatus };
        var status = candidates.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));
        if (!string.IsNullOrWhiteSpace(status))
        {
            return status.Trim();
        }

        return item.IsFixed ? "Fixed" : "";
    }

    public static bool IsDetectionFixed(VulnerabilityDto item)
    {
        return string.Equals(GetDetectionStatusValue(item), "fixed", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsDetectionFixed(DetectionDto item)
    {
        return string.Equals(item.Status?.Trim(), "fixed", StringComparison.OrdinalIgnoreCase)
            || string.Equals(item.Status?.Trim(), "corrigida", StringComparison.OrdinalIgnoreCase)
            || string.Equals(item.Status?.Trim(), "corrigido", StringComparison.OrdinalIgnoreCase);
    }

    public static string ClassifyOwner(DetectionDto detection)
    {
        var blob = ToSearchBlob(detection);
        if (HasAnyTerm(blob, ["WINDOWS SERVER 2008", "WINDOWS 2008", "SERVER 2008", "WINDOWS SERVER 2012", "WINDOWS 2012", "SERVER 2012", "2012 R2", "LEGADO", "LEGACY"])) return "Legados";
        if (HasAnyTerm($" {blob} ", ["ORACLE", "SQL SERVER", "MSSQL", "MYSQL", "MARIADB", "POSTGRESQL", "POSTGRES", "DATABASE", "BANCO", "DBA", "ORA", " SQL ", " DB "])) return "Banco de Dados";
        if (HasAnyTerm(blob, ["AMS", "APLICACAO", "APLICAÇÃO", "APPLICATION", "APP", "SISTEMA"])) return "Aplicações_AMS";
        if (HasAnyTerm(blob, ["WINDOWS", "MICROSOFT WINDOWS"])) return "Windows";
        if (HasAnyTerm(blob, ["LINUX", "SLES", "SUSE", "UBUNTU", "RED HAT", "RHEL", "CENTOS", "DEBIAN"])) return "Linux";
        return "Infraestrutura";
    }

    public static string ClassifyEnvironment(DetectionDto detection)
    {
        var blob = ToSearchBlob(detection);
        if (HasAnyTerm(blob, ["PRD_ALTA", "PRD ALTA", "PRODUCAO_ALTA", "PRODUÇÃO_ALTA", "PRODUCAO ALTA", "PRODUÇÃO ALTA"])) return "PRD_Alta";
        if (HasAnyTerm(blob, ["PRD_BAIXA", "PRD BAIXA", "PRODUCAO_BAIXA", "PRODUÇÃO_BAIXA", "PRODUCAO BAIXA", "PRODUÇÃO BAIXA"])) return "PRD_Baixa";
        if (HasAnyTerm(blob, ["DEV_QA", "DEV_QAS", "DEV QA", "DEV QAS", "DESENVOLVIMENTO", "QUALIDADE", "QA", "HML", "HOMOLOGAÇÃO", "HOMOLOGACAO"])) return "DEV_QAs";
        return "Não classificado";
    }

    public static string CalculatePriority(DetectionDto detection)
    {
        _ = int.TryParse(detection.Severity, out var severity);
        var environment = ClassifyEnvironment(detection);
        var tagsBlob = Strip($"{detection.HostTags}");
        var internetExposed = HasAnyTerm(tagsBlob, ["INTERNET", "EXTERNO", "EXTERNAL", "PUBLICO", "PÚBLICO"]);

        if (severity == 5 && (environment == "PRD_Alta" || internetExposed)) return "P0";
        if (severity == 5 && environment == "PRD_Baixa") return "P1";
        if (severity == 4 && environment == "PRD_Alta") return "P1";
        if (severity == 4 && environment == "PRD_Baixa") return "P2";
        if (severity == 5 && environment == "DEV_QAs") return "P2";
        if (severity == 4 && environment == "DEV_QAs") return "P3";
        if (severity == 3) return "P3";
        if (severity is 1 or 2) return "P4";
        return "Não classificado";
    }

    private static string ToSearchBlob(DetectionDto detection)
    {
        var parts = new[] { detection.Os, detection.HostTags, detection.HostDns, detection.Title, detection.Qid };
        return Strip(string.Join(' ', parts.Where(part => !string.IsNullOrWhiteSpace(part))));
    }

    private static string Strip(string value)
    {
        return SeverityNormalizer.StripAccents(value).ToUpperInvariant();
    }

    private static bool HasAnyTerm(string blob, IEnumerable<string> terms)
    {
        return terms.Any(term => blob.Contains(Strip(term), StringComparison.Ordinal));
    }
}

