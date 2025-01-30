using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Resources;
using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

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

        public static async Task<AuthorizationResult> McAuthorizeAsync(this IAuthorizationService service,
            ClaimsPrincipal principal, object? resource, ILogger? logger) {
            string resourceType = "NULL";
            Type type = resource?.GetType();
            if (type != null && resource != null) {
                resourceType = McRuleApprovedRequirement.FigureOutPolicyType(type, resource);
            }

            try {
                var result = await service.AuthorizeAsync(principal, resource, Globals.McPolicy);
                if (result.Succeeded) {
                    logger?.LogDebug($"Evaluation of resource type '{resourceType}' succeeded.");
                } else {
                    string failureMessages = "NONE PROVIDED";
                    var joinedMessages = String.Join(", ", result.Failure.FailureReasons.Select(reason => reason.Message));
                    if (!string.IsNullOrEmpty(joinedMessages)) { failureMessages = joinedMessages; }

                    logger?.LogWarning($"Evaluation of resource type '{resourceType}' failed: {failureMessages}");
                }

                return result;
            } catch (Exception ex) {
                if (logger != null) {
                    logger.LogError(ex, $"Uncaught exception in while evaluating resource rules for type '{resourceType}'");
                } else {
                    System.Diagnostics.Debug.WriteLine($"Uncaught exception in while evaluating resource rules for type '{resourceType}'");
                    System.Diagnostics.Debug.WriteLine($"Exception: '{ex.ToString()}'");
                }
                throw new Exception($"Uncaught exception in while evaluating resource rules for type '{resourceType}'", ex);
            }
        }

    }

    public static class Globals {
        public const string McPolicy = "McPolicy";
    }
}
