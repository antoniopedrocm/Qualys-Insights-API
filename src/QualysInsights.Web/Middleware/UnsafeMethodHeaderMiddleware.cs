namespace QualysInsights.Web.Middleware;

public sealed class UnsafeMethodHeaderMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext context)
    {
        if (HttpMethods.IsPost(context.Request.Method)
            || HttpMethods.IsPut(context.Request.Method)
            || HttpMethods.IsPatch(context.Request.Method)
            || HttpMethods.IsDelete(context.Request.Method))
        {
            var header = context.Request.Headers["X-Requested-With"].ToString();
            if (!string.Equals(header, "QualysInsights", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(header, "XMLHttpRequest", StringComparison.OrdinalIgnoreCase))
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await context.Response.WriteAsJsonAsync(new
                {
                    success = false,
                    error = "Cabeçalho de proteção ausente",
                    message = "Inclua o cabeçalho X-Requested-With para requisições que alteram estado."
                });
                return;
            }
        }

        await next(context);
    }
}

