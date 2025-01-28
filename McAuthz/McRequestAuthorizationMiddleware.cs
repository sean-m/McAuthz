using System;
using System.Net;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.CodeAnalysis.Elfie.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace McAuthz {
    public class McAuthorizationMiddleware {
        private readonly RequestDelegate _next;

        public McAuthorizationMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context, IServiceProvider serviceProvider) {
            using (var scope = serviceProvider.CreateScope()) {
                var mapper = scope.ServiceProvider.GetRequiredService<PolicyRequestMapperInterface>();
                var logger = scope.ServiceProvider.GetRequiredService<ILogger<McAuthorizationMiddleware>>();

                logger?.LogDebug($"RequestAuthorizationPolicy middleware invoked");

                if (!mapper?.IsAuthorized(context) ?? false) {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    return;
                }
            }

            await _next(context);
        }

        public async Task Run(HttpContext context) {

            await _next(context);
        }
    }
}
