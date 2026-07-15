using Microsoft.AspNetCore.Mvc;
using QualysInsights.Application.Models;

namespace QualysInsights.Web.Controllers;

[ApiController]
public abstract class ApiControllerBase : ControllerBase
{
    protected ObjectResult QueueResponse(QualysQueueException error, object? payload = null)
    {
        if (error.RetryAfterSeconds.HasValue)
        {
            Response.Headers.RetryAfter = Math.Max(1, error.RetryAfterSeconds.Value).ToString();
        }

        var body = new Dictionary<string, object?>
        {
            ["success"] = false,
            ["error"] = "Qualys job ainda em execução",
            ["message"] = string.IsNullOrWhiteSpace(error.Message) ? "O Qualys ainda está processando a consulta." : error.Message,
            ["callsToFinish"] = error.CallsToFinish,
            ["retryAfterSeconds"] = error.RetryAfterSeconds
        };

        if (payload is not null)
        {
            foreach (var property in payload.GetType().GetProperties())
            {
                if (string.Equals(property.Name, "success", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                body[char.ToLowerInvariant(property.Name[0]) + property.Name[1..]] = property.GetValue(payload);
            }
        }

        return StatusCode(StatusCodes.Status503ServiceUnavailable, body);
    }

    protected static object ErrorBody(string error, string message)
    {
        return new { success = false, error, message };
    }
}

