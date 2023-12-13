using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

using System;
using System.Collections.Generic;
using System.Text;

namespace McAuthz {

    public static class Extensions {
        public static IApplicationBuilder UseMcRequestAuthorizationPolicy(this IApplicationBuilder app) {
                        
            return app.UseMiddleware<McAuthorizationMiddleware>();
        }
    }

    public static class Globals {
        public const string McPolicy = "McPolicy";
    }
}
