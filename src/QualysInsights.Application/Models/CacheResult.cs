namespace QualysInsights.Application.Models;

public sealed class CacheResult<T>
{
    public required T Data { get; init; }
    public bool Cached { get; init; }
    public bool Stale { get; init; }
    public Exception? Error { get; init; }
}

