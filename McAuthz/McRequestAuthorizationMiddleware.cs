using System;
using System.Net;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace McAuthz {
    public class McAuthorizationMiddleware {
        private readonly RequestDelegate _next;
        private readonly ILogger _logger;
        private readonly PolicyRequestMapper _mapper;

        public McAuthorizationMiddleware(RequestDelegate next, PolicyRequestMapper mapper, ILogger<McAuthorizationMiddleware> logger)
        {
            _next = next;
            _logger = logger;
            _mapper = mapper;
        }

        public async Task Invoke(HttpContext context) {

            if (_logger != null) _logger.LogDebug($"RequestAuthorizationPolicy middleware invoked");

            if (!_mapper.IsAuthorized(context)) {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return;
            }

            await _next(context);
        }

        public async Task Run(HttpContext context) {
            if (_logger != null) _logger.LogDebug($"RequestAuthorizationPolicy middleware ran");

            await _next(context);
        }
    }
}
