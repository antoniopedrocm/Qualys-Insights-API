using QualysInsights.Application.DTOs;
using QualysInsights.Application.Interfaces;

namespace QualysInsights.IntegrationTests;

public sealed class FakeQualysClient : IQualysClient
{
    public Task<IReadOnlyList<HostDto>> GetHostListAsync(CancellationToken cancellationToken)
    {
        IReadOnlyList<HostDto> hosts =
        [
            new HostDto { Id = "1", Ip = "10.0.0.1", Dns = "srv01.local", Os = "Windows Server 2022", Tags = "PRD_ALTA" }
        ];
        return Task.FromResult(hosts);
    }

    public Task<IReadOnlyList<VulnerabilityDto>> GetVulnerabilitiesAsync(CancellationToken cancellationToken)
    {
        IReadOnlyList<VulnerabilityDto> vulnerabilities =
        [
            new VulnerabilityDto
            {
                DetectionId = "6385789118",
                UniqueVulnId = "6385789118",
                HostIp = "10.0.0.1",
                HostDns = "srv01.local",
                HostTags = "PRD_ALTA",
                Os = "Windows Server 2022",
                Qid = "100001",
                Severity = "5",
                Status = "Active",
                FirstFound = "2026-07-01T00:00:00Z",
                Title = "Sample",
                Solution = "Patch"
            },
            new VulnerabilityDto
            {
                DetectionId = "6385789119",
                UniqueVulnId = "6385789119",
                HostIp = "10.0.0.2",
                HostDns = "srv02.local",
                HostTags = "DEV_QA",
                Qid = "100002",
                Severity = "4",
                Status = "Fixed",
                IsFixed = true
            }
        ];
        return Task.FromResult(vulnerabilities);
    }

    public Task<IReadOnlyList<ScanDto>> GetScanListAsync(CancellationToken cancellationToken)
    {
        IReadOnlyList<ScanDto> scans = [new ScanDto { Ref = "scan/1", Title = "Weekly", State = "Finished" }];
        return Task.FromResult(scans);
    }

    public Task<DetectionDto?> GetDetectionByIdAsync(string detectionId, CancellationToken cancellationToken)
    {
        return Task.FromResult<DetectionDto?>(new DetectionDto { DetectionId = detectionId, HostTags = "DEV_QA", Status = "Fixed" });
    }

    public Task<IReadOnlyList<DetectionDto>> GetHostDetectionsWithDetailsAsync(CancellationToken cancellationToken)
    {
        IReadOnlyList<DetectionDto> detections =
        [
            new DetectionDto { DetectionId = "6385789118", HostIp = "10.0.0.1", HostDns = "srv01.local", HostTags = "PRD_ALTA", Qid = "100001", Severity = "5", Status = "Active", Title = "Sample", Solution = "Patch" }
        ];
        return Task.FromResult(detections);
    }
}

