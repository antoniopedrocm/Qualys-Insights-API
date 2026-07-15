using System.Xml.Linq;
using QualysInsights.Application.DTOs;

namespace QualysInsights.Infrastructure.Qualys;

public sealed class QualysQueueInfo
{
    public string Code { get; init; } = "";
    public int? CallsToFinish { get; init; }
    public int? RetryAfterSeconds { get; init; }
    public string Message { get; init; } = "Qualys job still running. Try again later.";
}

public sealed class QualysXmlParser
{
    public QualysQueueInfo? ParseQueueError(string? xmlData)
    {
        if (string.IsNullOrWhiteSpace(xmlData))
        {
            return null;
        }

        try
        {
            var document = XDocument.Parse(xmlData);
            var response = Find(document.Root, "RESPONSE") ?? document.Root;
            if (response is null)
            {
                return null;
            }

            var code = Value(response, "CODE");
            var callsRaw = FirstNonEmpty(Value(response, "CALLS_TO_FINISH"), Value(response, "CALL_TO_FINISH"), Value(response, "CALLS"));
            var callsToFinish = int.TryParse(callsRaw, out var parsedCalls) ? parsedCalls : (int?)null;
            var retryAfter = callsToFinish.HasValue ? Math.Max(1, callsToFinish.Value * 30) : (int?)null;
            var message = FirstNonEmpty(Value(response, "TEXT"), Value(response, "ERROR"), "Qualys job still running. Try again later.");

            return new QualysQueueInfo
            {
                Code = code,
                CallsToFinish = callsToFinish,
                RetryAfterSeconds = retryAfter,
                Message = message
            };
        }
        catch
        {
            return null;
        }
    }

    public IReadOnlyList<HostDto> ParseHosts(string xmlData)
    {
        var document = XDocument.Parse(xmlData);
        var hostList = Find(document.Root, "HOST_LIST");
        if (hostList is null)
        {
            return Array.Empty<HostDto>();
        }

        return Children(hostList, "HOST").Select(host => new HostDto
        {
            Id = Value(host, "ID"),
            Ip = Value(host, "IP"),
            TrackingMethod = Value(host, "TRACKING_METHOD"),
            Dns = Value(host, "DNS"),
            Netbios = Value(host, "NETBIOS"),
            Os = Value(host, "OS"),
            LastVulnScan = Value(host, "LAST_VULN_SCAN_DATETIME"),
            Tags = ParseTags(host)
        }).ToArray();
    }

    public IReadOnlyList<VulnerabilityDto> ParseVulnerabilities(string xmlData)
    {
        var document = XDocument.Parse(xmlData);
        var hostList = Find(document.Root, "HOST_LIST");
        if (hostList is null)
        {
            return Array.Empty<VulnerabilityDto>();
        }

        var vulnerabilities = new List<VulnerabilityDto>();
        foreach (var host in Children(hostList, "HOST"))
        {
            var hostId = FirstNonEmpty(Value(host, "ID"), Value(host, "IP"));
            var hostIp = Value(host, "IP");
            var hostDns = Value(host, "DNS");
            var os = Value(host, "OS");
            var hostTags = ParseTags(host);
            var detectionList = Child(host, "DETECTION_LIST");
            if (detectionList is null)
            {
                continue;
            }

            foreach (var detection in Children(detectionList, "DETECTION"))
            {
                var vulnInfo = Child(detection, "VULN_INFO");
                var detectionId = FirstNonEmpty(Value(detection, "UNIQUE_VULN_ID"), Value(vulnInfo, "UNIQUE_VULN_ID"), Value(detection, "DETECTION_ID"));
                var type = Value(detection, "TYPE");
                var status = GetDetectionStatusValue(detection);

                vulnerabilities.Add(new VulnerabilityDto
                {
                    DetectionId = detectionId,
                    UniqueVulnId = detectionId,
                    HostId = hostId,
                    HostIp = hostIp,
                    HostDns = hostDns,
                    HostTags = hostTags,
                    Os = os,
                    Qid = Value(detection, "QID"),
                    Type = type,
                    TypeDetected = type.ToUpperInvariant() switch
                    {
                        "CONFIRMED" => "Confirmed",
                        "POTENTIAL" => "Potential",
                        _ => ""
                    },
                    Severity = Value(detection, "SEVERITY"),
                    Status = status,
                    DetectionStatus = status,
                    FindingStatus = Value(detection, "FINDING_STATUS"),
                    State = Value(detection, "STATE"),
                    IsFixed = string.Equals(status, "fixed", StringComparison.OrdinalIgnoreCase),
                    FirstFound = Value(detection, "FIRST_FOUND_DATETIME"),
                    LastFound = Value(detection, "LAST_FOUND_DATETIME"),
                    Port = Value(detection, "PORT"),
                    Protocol = Value(detection, "PROTOCOL"),
                    Ssl = Value(detection, "SSL"),
                    Title = Value(vulnInfo, "TITLE"),
                    Solution = SolutionValue(Child(vulnInfo, "SOLUTION")),
                    Results = Value(detection, "RESULTS"),
                    LastSeen = FirstNonEmpty(Value(detection, "LAST_FOUND_DATETIME"), Value(detection, "LAST_TEST_DATETIME"))
                });
            }
        }

        return vulnerabilities;
    }

    public IReadOnlyList<DetectionDto> ParseHostDetections(string xmlData)
    {
        var document = XDocument.Parse(xmlData);
        var hostList = Find(document.Root, "HOST_LIST");
        if (hostList is null)
        {
            return Array.Empty<DetectionDto>();
        }

        var detections = new List<DetectionDto>();
        foreach (var host in Children(hostList, "HOST"))
        {
            var hostTags = ParseTags(host);
            var detectionList = Child(host, "DETECTION_LIST");
            if (detectionList is null)
            {
                continue;
            }

            detections.AddRange(Children(detectionList, "DETECTION").Select(detection => new DetectionDto
            {
                DetectionId = FirstNonEmpty(Value(detection, "UNIQUE_VULN_ID"), Value(detection, "DETECTION_ID")),
                UniqueVulnId = FirstNonEmpty(Value(detection, "UNIQUE_VULN_ID"), Value(detection, "DETECTION_ID")),
                HostIp = Value(host, "IP"),
                HostDns = Value(host, "DNS"),
                HostTags = hostTags,
                Os = Value(host, "OS"),
                Qid = Value(detection, "QID"),
                Severity = Value(detection, "SEVERITY"),
                Status = GetDetectionStatusValue(detection),
                FirstFound = Value(detection, "FIRST_FOUND_DATETIME"),
                LastFound = Value(detection, "LAST_FOUND_DATETIME")
            }));
        }

        return detections;
    }

    public IReadOnlyList<DetectionDto> ParseDetection(string xmlData, string fallbackId)
    {
        var detections = ParseHostDetections(xmlData).ToList();
        foreach (var detection in detections.Where(detection => string.IsNullOrWhiteSpace(detection.DetectionId)))
        {
            detection.DetectionId = fallbackId;
        }

        return detections;
    }

    public Dictionary<string, KnowledgeBaseDetailDto> ParseKnowledgeBase(string xmlData)
    {
        var document = XDocument.Parse(xmlData);
        var vulnList = Find(document.Root, "VULN_LIST");
        if (vulnList is null)
        {
            return new Dictionary<string, KnowledgeBaseDetailDto>(StringComparer.OrdinalIgnoreCase);
        }

        return Children(vulnList, "VULN")
            .Select(vuln => new { Qid = FirstNonEmpty(Value(vuln, "QID"), Value(vuln, "ID")), Vuln = vuln })
            .Where(item => !string.IsNullOrWhiteSpace(item.Qid))
            .ToDictionary(
                item => item.Qid,
                item => new KnowledgeBaseDetailDto
                {
                    UniqueVulnId = Value(item.Vuln, "UNIQUE_VULN_ID"),
                    Title = Value(item.Vuln, "TITLE"),
                    Solution = SolutionValue(Child(item.Vuln, "SOLUTION"))
                },
                StringComparer.OrdinalIgnoreCase);
    }

    public IReadOnlyList<ScanDto> ParseScans(string xmlData)
    {
        var document = XDocument.Parse(xmlData);
        var scanList = Find(document.Root, "SCAN_LIST");
        if (scanList is null)
        {
            return Array.Empty<ScanDto>();
        }

        return Children(scanList, "SCAN").Select(scan => new ScanDto
        {
            Ref = Value(scan, "REF"),
            Title = Value(scan, "TITLE"),
            Type = Value(scan, "TYPE"),
            LaunchDate = Value(scan, "LAUNCH_DATETIME"),
            State = Value(Child(scan, "STATE"), "STATE_NAME"),
            Target = Value(scan, "TARGET")
        }).ToArray();
    }

    private static string ParseTags(XElement host)
    {
        var tags = Child(host, "TAGS");
        if (tags is null)
        {
            return "";
        }

        return string.Join(", ", Children(tags, "TAG")
            .Select(tag => FirstNonEmpty(Value(tag, "NAME"), tag.Value))
            .Where(tag => !string.IsNullOrWhiteSpace(tag))
            .Select(tag => tag.Replace("/", "_", StringComparison.Ordinal).Replace(" ", "_", StringComparison.Ordinal)));
    }

    private static string GetDetectionStatusValue(XElement detection)
    {
        var firstStatus = FirstNonEmpty(
            Value(detection, "STATUS"),
            Value(detection, "STATE"),
            Value(detection, "DETECTION_STATUS"),
            Value(detection, "FINDING_STATUS"));

        if (!string.IsNullOrWhiteSpace(firstStatus))
        {
            return firstStatus.Trim();
        }

        var fixedCandidate = FirstNonEmpty(Value(detection, "IS_FIXED"), Value(detection, "FIXED"));
        return fixedCandidate.Trim().ToLowerInvariant() switch
        {
            "true" or "1" or "yes" or "sim" => "Fixed",
            "false" or "0" or "no" or "nao" or "não" => "Active",
            _ => ""
        };
    }

    private static string SolutionValue(XElement? element)
    {
        if (element is null)
        {
            return "";
        }

        return FirstNonEmpty(Value(element, "SOLUTION"), element.Value);
    }

    private static XElement? Find(XElement? root, string localName)
    {
        return root?.DescendantsAndSelf().FirstOrDefault(element => element.Name.LocalName == localName);
    }

    private static XElement? Child(XElement? root, string localName)
    {
        return root?.Elements().FirstOrDefault(element => element.Name.LocalName == localName);
    }

    private static IEnumerable<XElement> Children(XElement root, string localName)
    {
        return root.Elements().Where(element => element.Name.LocalName == localName);
    }

    private static string Value(XElement? root, string localName)
    {
        return Child(root, localName)?.Value?.Trim() ?? "";
    }

    private static string FirstNonEmpty(params string?[] values)
    {
        return values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? "";
    }
}

