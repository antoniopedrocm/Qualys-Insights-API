using System.Text;
using ClosedXML.Excel;
using QualysInsights.Application.DTOs;
using QualysInsights.Application.Interfaces;
using QualysInsights.Application.Services;

namespace QualysInsights.Infrastructure.Export;

public sealed class SpreadsheetExportService : IExportService
{
    public byte[] BuildVulnerabilitiesWorkbook(IReadOnlyList<VulnerabilityDto> vulnerabilities)
    {
        using var workbook = new XLWorkbook();
        var worksheet = workbook.Worksheets.Add("Vulnerabilidades");
        var columns = new (string Header, Func<VulnerabilityDto, object?> Value, double Width)[]
        {
            ("Detection ID", v => FirstNonEmpty(v.UniqueVulnId, v.DetectionId), 20),
            ("DNS", v => v.HostDns, 30),
            ("Host IP", v => v.HostIp, 15),
            ("Sistema Operacional", v => v.Os, 25),
            ("Titulo", v => v.Title, 40),
            ("Solucao", v => v.Solution, 40),
            ("Resultados", v => v.Results, 50),
            ("Severidade", v => v.Severity, 12),
            ("Status", v => v.Status, 12),
            ("QID", v => v.Qid, 10),
            ("Porta", v => v.Port, 10),
            ("Primeira Deteccao", v => v.FirstFound, 20)
        };

        WriteTable(worksheet, columns, vulnerabilities);
        worksheet.Range(1, 1, Math.Max(1, vulnerabilities.Count + 1), columns.Length).SetAutoFilter();
        using var stream = new MemoryStream();
        workbook.SaveAs(stream);
        return stream.ToArray();
    }

    public byte[] BuildVulnerabilitiesCsv(IReadOnlyList<VulnerabilityDto> vulnerabilities)
    {
        var headers = new[] { "Detection ID", "DNS", "Host IP", "Sistema Operacional", "Titulo", "Solucao", "Resultados", "Severidade", "Status", "QID", "Porta", "Primeira Deteccao" };
        var rows = vulnerabilities.Select(v => new[]
        {
            FirstNonEmpty(v.DetectionId, v.UniqueVulnId),
            v.HostDns,
            v.HostIp,
            v.Os,
            v.Title,
            v.Solution,
            v.Results,
            v.Severity,
            v.Status,
            v.Qid,
            v.Port,
            v.FirstFound
        });

        return BuildCsv(headers, rows);
    }

    public byte[] BuildDetectionsWorkbook(IReadOnlyList<DetectionDto> detections)
    {
        using var workbook = new XLWorkbook();
        var enriched = detections.Select(detection =>
        {
            detection.Priority = string.IsNullOrWhiteSpace(detection.Priority) ? BusinessClassifiers.CalculatePriority(detection) : detection.Priority;
            detection.OwnerArea = string.IsNullOrWhiteSpace(detection.OwnerArea) ? BusinessClassifiers.ClassifyOwner(detection) : detection.OwnerArea;
            detection.Environment = string.IsNullOrWhiteSpace(detection.Environment) ? BusinessClassifiers.ClassifyEnvironment(detection) : detection.Environment;
            return detection;
        }).ToArray();

        var columns = DetectionColumns();
        WriteTable(workbook.Worksheets.Add("Base Completa"), columns, enriched);
        AddSimpleSheet(workbook, "Top Prioridades", enriched.Where(v => v.Priority is "P0" or "P1").ToArray(), columns);
        AddSimpleSheet(workbook, "PRD_Alta", enriched.Where(v => v.Environment == "PRD_Alta").ToArray(), columns);
        AddSimpleSheet(workbook, "PRD_Baixa", enriched.Where(v => v.Environment == "PRD_Baixa").ToArray(), columns);
        AddSimpleSheet(workbook, "DEV_QAs", enriched.Where(v => v.Environment == "DEV_QAs").ToArray(), columns);
        AddSimpleSheet(workbook, "Windows", enriched.Where(v => v.OwnerArea == "Windows").ToArray(), columns);
        AddSimpleSheet(workbook, "Linux", enriched.Where(v => v.OwnerArea == "Linux").ToArray(), columns);
        AddSimpleSheet(workbook, "Banco de Dados", enriched.Where(v => v.OwnerArea == "Banco de Dados").ToArray(), columns);
        AddSimpleSheet(workbook, "Aplicações_AMS", enriched.Where(v => v.OwnerArea == "Aplicações_AMS").ToArray(), columns);
        AddSimpleSheet(workbook, "Infraestrutura", enriched.Where(v => v.OwnerArea == "Infraestrutura").ToArray(), columns);
        AddSimpleSheet(workbook, "Legados", enriched.Where(v => v.OwnerArea == "Legados").ToArray(), columns);
        AddSummarySheet(workbook, enriched);

        using var stream = new MemoryStream();
        workbook.SaveAs(stream);
        return stream.ToArray();
    }

    public byte[] BuildDetectionsCsv(IReadOnlyList<DetectionDto> detections)
    {
        var headers = new[] { "hostIp", "hostDns", "hostTags", "os", "qid", "severity", "status", "firstFound", "lastFound", "title", "solution" };
        var rows = detections.Select(detection => new[]
        {
            detection.HostIp,
            detection.HostDns,
            detection.HostTags,
            detection.Os,
            detection.Qid,
            detection.Severity,
            detection.Status,
            detection.FirstFound,
            detection.LastFound,
            detection.Title,
            detection.Solution
        });

        return BuildCsv(headers, rows);
    }

    private static (string Header, Func<DetectionDto, object?> Value, double Width)[] DetectionColumns()
    {
        return
        [
            ("priority", d => d.Priority, 10),
            ("ownerArea", d => d.OwnerArea, 18),
            ("environment", d => d.Environment, 16),
            ("detectionId", d => d.DetectionId, 20),
            ("uniqueVulnId", d => d.UniqueVulnId, 20),
            ("hostDns", d => d.HostDns, 30),
            ("hostIp", d => d.HostIp, 15),
            ("os", d => d.Os, 25),
            ("hostTags", d => d.HostTags, 30),
            ("qid", d => d.Qid, 10),
            ("title", d => d.Title, 50),
            ("severity", d => d.Severity, 10),
            ("status", d => d.Status, 14),
            ("typeDetected", _ => "", 14),
            ("firstFound", d => d.FirstFound, 22),
            ("lastFound", d => d.LastFound, 22),
            ("port", _ => "", 8),
            ("protocol", _ => "", 10),
            ("ssl", _ => "", 8),
            ("results", _ => "", 60),
            ("solution", d => d.Solution, 60)
        ];
    }

    private static void WriteTable<T>(IXLWorksheet worksheet, IReadOnlyList<(string Header, Func<T, object?> Value, double Width)> columns, IReadOnlyList<T> rows)
    {
        for (var col = 0; col < columns.Count; col++)
        {
            var cell = worksheet.Cell(1, col + 1);
            cell.Value = columns[col].Header;
            cell.Style.Font.Bold = true;
            cell.Style.Fill.BackgroundColor = XLColor.FromHtml("#4472C4");
            cell.Style.Font.FontColor = XLColor.White;
            worksheet.Column(col + 1).Width = columns[col].Width;
            worksheet.Column(col + 1).Style.Alignment.WrapText = true;
        }

        for (var row = 0; row < rows.Count; row++)
        {
            for (var col = 0; col < columns.Count; col++)
            {
                worksheet.Cell(row + 2, col + 1).Value = ProtectForSpreadsheet(columns[col].Value(rows[row]));
            }
        }
    }

    private static void AddSimpleSheet(XLWorkbook workbook, string name, IReadOnlyList<DetectionDto> rows, IReadOnlyList<(string Header, Func<DetectionDto, object?> Value, double Width)> columns)
    {
        WriteTable(workbook.Worksheets.Add(name), columns, rows);
    }

    private static void AddSummarySheet(XLWorkbook workbook, IReadOnlyList<DetectionDto> detections)
    {
        var worksheet = workbook.Worksheets.Add("Resumo Executivo");
        var row = 1;
        worksheet.Cell(row++, 1).Value = "Data/Hora geração";
        worksheet.Cell(row - 1, 2).Value = DateTimeOffset.UtcNow.ToString("O");
        worksheet.Cell(row++, 1).Value = "Total geral";
        worksheet.Cell(row - 1, 2).Value = detections.Count;
        row++;

        AddSection("Total por severidade", CountBy(detections, d => d.Severity), worksheet, ref row);
        AddSection("Total por prioridade", CountBy(detections, d => d.Priority), worksheet, ref row);
        AddSection("Total por ambiente", CountBy(detections, d => d.Environment), worksheet, ref row);
        AddSection("Total por área responsável", CountBy(detections, d => d.OwnerArea), worksheet, ref row);
        AddSection("Total por status", CountBy(detections, d => d.Status), worksheet, ref row);
        AddSection("Top 10 QIDs", CountBy(detections, d => d.Qid).OrderByDescending(item => item.Value).Take(10), worksheet, ref row);
        AddSection("Top 10 Hosts", CountBy(detections, d => d.HostDns).OrderByDescending(item => item.Value).Take(10), worksheet, ref row);
        worksheet.Columns().AdjustToContents();
    }

    private static Dictionary<string, int> CountBy(IReadOnlyList<DetectionDto> detections, Func<DetectionDto, string> selector)
    {
        return detections
            .GroupBy(item => string.IsNullOrWhiteSpace(selector(item)) ? "Não classificado" : selector(item), StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.Count(), StringComparer.OrdinalIgnoreCase);
    }

    private static void AddSection(string title, IEnumerable<KeyValuePair<string, int>> values, IXLWorksheet worksheet, ref int row)
    {
        worksheet.Cell(row++, 1).Value = title;
        foreach (var (key, value) in values)
        {
            worksheet.Cell(row, 1).Value = ProtectForSpreadsheet(key);
            worksheet.Cell(row++, 2).Value = value;
        }

        row++;
    }

    private static byte[] BuildCsv(IReadOnlyList<string> headers, IEnumerable<IReadOnlyList<string>> rows)
    {
        var builder = new StringBuilder();
        builder.AppendLine(string.Join(',', headers.Select(EscapeCsv)));
        foreach (var row in rows)
        {
            builder.AppendLine(string.Join(',', row.Select(value => EscapeCsv(ProtectForSpreadsheet(value).ToString() ?? ""))));
        }

        return Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(builder.ToString())).ToArray();
    }

    private static string EscapeCsv(string? value)
    {
        var text = value ?? "";
        return $"\"{text.Replace("\"", "\"\"", StringComparison.Ordinal)}\"";
    }

    private static string ProtectForSpreadsheet(object? value)
    {
        var text = value?.ToString() ?? "";
        if (text.Length > 0 && text[0] is '=' or '+' or '-' or '@')
        {
            return $"'{text}";
        }

        return text;
    }

    private static string FirstNonEmpty(params string?[] values)
    {
        return values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? "";
    }
}
