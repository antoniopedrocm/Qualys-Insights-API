using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using QualysInsights.Application.DTOs;
using QualysInsights.Application.Interfaces;
using QualysInsights.Application.Models;
using QualysInsights.Application.Options;

namespace QualysInsights.Infrastructure.Qualys;

public sealed class QualysClient(
    HttpClient httpClient,
    QualysXmlParser parser,
    IOptions<QualysOptions> qualysOptions,
    IOptions<CacheOptions> cacheOptions,
    ILogger<QualysClient> logger) : IQualysClient
{
    private readonly QualysOptions _options = qualysOptions.Value;
    private readonly CacheOptions _cacheOptions = cacheOptions.Value;
    private readonly ConcurrentDictionary<string, KnowledgeBaseDetailDto> _knowledgeBaseCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim _knowledgeBaseLock = new(1, 1);
    private DateTimeOffset _knowledgeBaseLastUpdate = DateTimeOffset.MinValue;

    public async Task<IReadOnlyList<HostDto>> GetHostListAsync(CancellationToken cancellationToken)
    {
        var xml = await GetStringAsync("/api/2.0/fo/asset/host/", new Dictionary<string, string>
        {
            ["action"] = "list",
            ["truncation_limit"] = "0",
            ["show_tags"] = "1"
        }, cancellationToken);

        var hosts = parser.ParseHosts(xml);
        logger.LogInformation("Qualys hosts parsed. Count={HostCount}", hosts.Count);
        return hosts;
    }

    public async Task<IReadOnlyList<VulnerabilityDto>> GetVulnerabilitiesAsync(CancellationToken cancellationToken)
    {
        var xml = await GetDetectionListWithQueueHandlingAsync(1000, cancellationToken);
        var vulnerabilities = parser.ParseVulnerabilities(xml);
        var qids = vulnerabilities.Select(vuln => vuln.Qid).Where(qid => !string.IsNullOrWhiteSpace(qid)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var kbDetails = await FetchKnowledgeBaseDetailsAsync(qids, cancellationToken);

        foreach (var vuln in vulnerabilities)
        {
            if (kbDetails.TryGetValue(vuln.Qid, out var kb))
            {
                vuln.UniqueVulnId = FirstNonEmpty(vuln.DetectionId, vuln.UniqueVulnId, kb.UniqueVulnId);
                vuln.DetectionId = FirstNonEmpty(vuln.DetectionId, vuln.UniqueVulnId);
                vuln.Title = FirstNonEmpty(vuln.Title, kb.Title);
                vuln.Solution = FirstNonEmpty(vuln.Solution, kb.Solution);
            }
        }

        logger.LogInformation("Qualys vulnerabilities parsed. Count={VulnerabilityCount} Qids={QidCount}", vulnerabilities.Count, qids.Length);
        return vulnerabilities;
    }

    public async Task<IReadOnlyList<ScanDto>> GetScanListAsync(CancellationToken cancellationToken)
    {
        var xml = await GetStringAsync("/api/2.0/fo/scan/", new Dictionary<string, string>
        {
            ["action"] = "list"
        }, cancellationToken);

        return parser.ParseScans(xml);
    }

    public async Task<DetectionDto?> GetDetectionByIdAsync(string detectionId, CancellationToken cancellationToken)
    {
        var xml = await GetStringAsync("/api/2.0/fo/asset/host/vm/detection/", new Dictionary<string, string>
        {
            ["action"] = "list",
            ["detection_ids"] = detectionId,
            ["output_format"] = "XML",
            ["show_tags"] = "1"
        }, cancellationToken);

        return parser.ParseDetection(xml, detectionId).FirstOrDefault();
    }

    public async Task<IReadOnlyList<DetectionDto>> GetHostDetectionsWithDetailsAsync(CancellationToken cancellationToken)
    {
        var xml = await GetStringAsync("/api/2.0/fo/asset/host/vm/detection/", new Dictionary<string, string>
        {
            ["action"] = "list",
            ["truncation_limit"] = "0",
            ["output_format"] = "XML",
            ["show_tags"] = "1"
        }, cancellationToken);

        var detections = parser.ParseHostDetections(xml).ToArray();
        var qids = detections.Select(detection => detection.Qid).Where(qid => !string.IsNullOrWhiteSpace(qid)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var kbDetails = await FetchKnowledgeBaseDetailsAsync(qids, cancellationToken);

        foreach (var detection in detections)
        {
            if (kbDetails.TryGetValue(detection.Qid, out var detail))
            {
                detection.UniqueVulnId = FirstNonEmpty(detection.UniqueVulnId, detail.UniqueVulnId);
                detection.Title = FirstNonEmpty(detection.Title, detail.Title);
                detection.Solution = FirstNonEmpty(detection.Solution, detail.Solution);
            }
        }

        return detections;
    }

    private async Task<string> GetDetectionListWithQueueHandlingAsync(int truncationLimit, CancellationToken cancellationToken)
    {
        var parameters = new Dictionary<string, string>
        {
            ["action"] = "list",
            ["truncation_limit"] = truncationLimit.ToString(),
            ["status"] = "New,Active,Re-Opened,Fixed",
            ["output_format"] = "XML",
            ["show_tags"] = "1"
        };

        var response = await SendAsync(HttpMethod.Get, "/api/2.0/fo/asset/host/vm/detection/", parameters, cancellationToken);
        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        if (response.StatusCode == HttpStatusCode.Conflict)
        {
            var queueInfo = parser.ParseQueueError(content);
            if (queueInfo?.Code == "1960")
            {
                throw new QualysQueueException(queueInfo.Message, queueInfo.Code, queueInfo.CallsToFinish, queueInfo.RetryAfterSeconds);
            }

            logger.LogWarning("Qualys detection list returned HTTP 409 without queue code 1960. Retrying with truncation limit 500.");
            response.Dispose();
            if (truncationLimit != 500)
            {
                return await GetDetectionListWithQueueHandlingAsync(500, cancellationToken);
            }
        }

        EnsureSuccess(response, content, "/api/2.0/fo/asset/host/vm/detection/");
        return content;
    }

    private async Task<Dictionary<string, KnowledgeBaseDetailDto>> FetchKnowledgeBaseDetailsAsync(IReadOnlyList<string> qids, CancellationToken cancellationToken)
    {
        await _knowledgeBaseLock.WaitAsync(cancellationToken);
        try
        {
            if (DateTimeOffset.UtcNow - _knowledgeBaseLastUpdate > TimeSpan.FromSeconds(_cacheOptions.DefaultTtlSeconds))
            {
                _knowledgeBaseCache.Clear();
                _knowledgeBaseLastUpdate = DateTimeOffset.MinValue;
            }
        }
        finally
        {
            _knowledgeBaseLock.Release();
        }

        var results = new Dictionary<string, KnowledgeBaseDetailDto>(StringComparer.OrdinalIgnoreCase);
        foreach (var qid in qids)
        {
            if (_knowledgeBaseCache.TryGetValue(qid, out var cached))
            {
                results[qid] = cached;
            }
        }

        var missing = qids.Where(qid => !results.ContainsKey(qid)).ToArray();
        if (missing.Length == 0)
        {
            logger.LogInformation("Knowledge Base cache hit. Qids={QidCount}", qids.Count);
            return results;
        }

        logger.LogInformation("Knowledge Base cache miss. MissingQids={MissingQidCount}", missing.Length);
        var batches = missing.Chunk(_options.KnowledgeBaseBatchSize).ToArray();
        using var semaphore = new SemaphoreSlim(_options.MaxKnowledgeBaseConcurrency, _options.MaxKnowledgeBaseConcurrency);
        var tasks = batches.Select(async batch =>
        {
            await semaphore.WaitAsync(cancellationToken);
            try
            {
                var xml = await GetStringAsync("/api/2.0/fo/knowledge_base/vuln/", new Dictionary<string, string>
                {
                    ["action"] = "list",
                    ["ids"] = string.Join(',', batch)
                }, cancellationToken);
                return parser.ParseKnowledgeBase(xml);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogWarning(ex, "Failed to fetch Knowledge Base batch. QidCount={QidCount}", batch.Length);
                return new Dictionary<string, KnowledgeBaseDetailDto>(StringComparer.OrdinalIgnoreCase);
            }
            finally
            {
                semaphore.Release();
            }
        }).ToArray();

        foreach (var parsed in await Task.WhenAll(tasks))
        {
            foreach (var (qid, detail) in parsed)
            {
                results[qid] = detail;
                _knowledgeBaseCache[qid] = detail;
            }
        }

        _knowledgeBaseLastUpdate = DateTimeOffset.UtcNow;
        return results;
    }

    private async Task<string> GetStringAsync(string path, IReadOnlyDictionary<string, string> parameters, CancellationToken cancellationToken)
    {
        using var response = await SendAsync(HttpMethod.Get, path, parameters, cancellationToken);
        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        EnsureSuccess(response, content, path);
        return content;
    }

    private async Task<HttpResponseMessage> SendAsync(HttpMethod method, string path, IReadOnlyDictionary<string, string> parameters, CancellationToken cancellationToken)
    {
        var requestUri = BuildRequestUri(path, parameters);
        var attempt = 0;

        while (true)
        {
            attempt++;
            using var request = new HttpRequestMessage(method, requestUri);
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{_options.Username}:{_options.Password}")));
            request.Headers.Add("X-Requested-With", "API");

            try
            {
                var started = DateTimeOffset.UtcNow;
                var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                var elapsed = DateTimeOffset.UtcNow - started;
                logger.LogInformation("Qualys request completed. Path={Path} StatusCode={StatusCode} DurationMs={DurationMs}", path, (int)response.StatusCode, elapsed.TotalMilliseconds);

                if (!ShouldRetry(response.StatusCode) || attempt > _options.MaxTransientRetries)
                {
                    return response;
                }

                var delay = GetRetryDelay(response, attempt);
                response.Dispose();
                await Task.Delay(delay, cancellationToken);
            }
            catch (Exception ex) when (IsTransientException(ex) && attempt <= _options.MaxTransientRetries)
            {
                var delay = ExponentialDelay(attempt);
                logger.LogWarning(ex, "Transient Qualys request failure. Path={Path} Attempt={Attempt} DelayMs={DelayMs}", path, attempt, delay.TotalMilliseconds);
                await Task.Delay(delay, cancellationToken);
            }
        }
    }

    private Uri BuildRequestUri(string path, IReadOnlyDictionary<string, string> parameters)
    {
        var query = string.Join('&', parameters.Select(parameter =>
            $"{Uri.EscapeDataString(parameter.Key)}={Uri.EscapeDataString(parameter.Value)}"));
        return new Uri($"{path}?{query}", UriKind.Relative);
    }

    private static bool ShouldRetry(HttpStatusCode statusCode)
    {
        var code = (int)statusCode;
        return statusCode is HttpStatusCode.RequestTimeout or HttpStatusCode.TooManyRequests
            || code is >= 500 and <= 599;
    }

    private static bool IsTransientException(Exception ex)
    {
        return ex is HttpRequestException or TaskCanceledException;
    }

    private static TimeSpan GetRetryDelay(HttpResponseMessage response, int attempt)
    {
        if (response.Headers.RetryAfter?.Delta is { } delta)
        {
            return delta;
        }

        return ExponentialDelay(attempt);
    }

    private static TimeSpan ExponentialDelay(int attempt)
    {
        return TimeSpan.FromSeconds(Math.Min(30, Math.Pow(2, attempt)));
    }

    private static void EnsureSuccess(HttpResponseMessage response, string content, string path)
    {
        if (response.IsSuccessStatusCode)
        {
            return;
        }

        var safeContent = content.Length > 500 ? content[..500] : content;
        throw new HttpRequestException($"Qualys request failed for {path}. HTTP {(int)response.StatusCode} {response.ReasonPhrase} - {safeContent}", null, response.StatusCode);
    }

    private static string FirstNonEmpty(params string?[] values)
    {
        return values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? "";
    }
}

