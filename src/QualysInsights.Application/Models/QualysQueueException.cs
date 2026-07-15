namespace QualysInsights.Application.Models;

public sealed class QualysQueueException : Exception
{
    public QualysQueueException(string message, string code, int? callsToFinish, int? retryAfterSeconds)
        : base(message)
    {
        Code = code;
        CallsToFinish = callsToFinish;
        RetryAfterSeconds = retryAfterSeconds;
    }

    public string Code { get; }
    public int? CallsToFinish { get; }
    public int? RetryAfterSeconds { get; }
}

