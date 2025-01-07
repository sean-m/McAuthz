using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace McAuthz {

    public static class Extensions {
        public static IApplicationBuilder UseMcAuthorization(this IApplicationBuilder app) {
            return app.UseMiddleware<McAuthorizationMiddleware>();
        }

        /// <summary>
        /// VisualBasic's string comparison with wildcard support.
        /// </summary>
        /// <param name="Base">The value to check.</param>
        /// <param name="Pattern">The pattern compared to 'Base'. Supports simple wildcards: *, ?.
        /// </param>
        /// <returns></returns>
        public static bool Like(this string Base, string Pattern, bool CaseSensitive = false) {
            var pattern = $"^{WildCardToRegular(Pattern)}$";
            var options = RegexOptions.CultureInvariant | RegexOptions.IgnoreCase;  // Case insensitive is the default.
            if (CaseSensitive) { options = options ^ RegexOptions.IgnoreCase; }
            return Regex.IsMatch(Base, pattern, options);
        }

        /// <summary>
        /// Decompose simple wildcard characters in to their regex equals.
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        private static String WildCardToRegular(String value) {
            return Regex.Escape(value).Replace("\\?", ".").Replace("\\*", ".*");
        }
    }

    public static class Globals {
        public const string McPolicy = "McPolicy";
    }
}
