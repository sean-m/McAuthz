using Microsoft.AspNetCore.Builder;
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
