using Microsoft.AspNetCore.Mvc;
using QualysInsights.Application.Models;

namespace QualysInsights.Web.Middleware;

public sealed class ExceptionHandlingMiddleware(RequestDelegate next, IProblemDetailsService problemDetailsService, ILogger<ExceptionHandlingMiddleware> logger)
{
    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await next(context);
        }
        catch (QualysQueueException ex)
        {
            logger.LogWarning(ex, "Qualys queue response.");
            if (ex.RetryAfterSeconds.HasValue)
            {
                context.Response.Headers.RetryAfter = ex.RetryAfterSeconds.Value.ToString();
            }

            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            await context.Response.WriteAsJsonAsync(new
            {
                success = false,
                error = "Qualys job ainda em execução",
                message = ex.Message,
                callsToFinish = ex.CallsToFinish,
                retryAfterSeconds = ex.RetryAfterSeconds
            });
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Unhandled request failure.");
            context.Response.StatusCode = StatusCodes.Status500InternalServerError;
            await problemDetailsService.WriteAsync(new ProblemDetailsContext
            {
                HttpContext = context,
                ProblemDetails = new ProblemDetails
                {
                    Status = StatusCodes.Status500InternalServerError,
                    Title = "Erro interno",
                    Detail = context.RequestServices.GetRequiredService<IHostEnvironment>().IsDevelopment()
                        ? ex.Message
                        : "Ocorreu um erro ao processar a requisição."
                }
            });
        }
    }
}

