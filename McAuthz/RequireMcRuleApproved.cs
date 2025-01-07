using McAuthz.Interfaces;
using McAuthz.Policy;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text;

namespace McAuthz
{
    public class RequireMcRuleApproved : IAuthorizationRequirement {
        private RuleProviderInterface  rules;
        private ILogger? logger;

        /// <summary>
        /// This is the requirement that associates McRule policies with a given
        /// controller. The requirement handler invokes methods on this requirement
        /// as needed.
        /// In order to facilitate hot-loaded rules, the constructor takes
        /// a Func which is called to fetch the rule set on each evaulation. Caching
        /// and optimization can happen upstream but if this is what's slowing your
        /// app down, what in the world are you doing with these rules?
        /// </summary>
        /// <param name="rules"></param>
        ///
        public RequireMcRuleApproved(RuleProviderInterface rules) {
            this.rules = rules;
        }
        public RequireMcRuleApproved(ILogger logger, RuleProviderInterface rules) {
            this.logger = logger;
            this.rules = rules;
        }

        internal bool IsAuthorized(AuthorizationHandlerContext context) {
            var principal = context.User;

            dynamic path = "*";
            dynamic action = "GET";

            bool isResponse = false;

            // Get controller from route data in context. The netstandard2.0 version
            // of DefaultHttpContext.Request doesn't have the RouteValues property
            // so we get it by reflection.
            // TODO refactor this into a more robust method with progressive fallback.
            IDictionary<string, object> route = new Dictionary<string, object>();
            if (context.Resource is DefaultHttpContext dhc) {
                isResponse = dhc.Response.HasStarted;
                Type dhcType = dhc.Request.GetType();
                var routeData = dhcType.GetProperties().FirstOrDefault(x => x.Name == "RouteValues");
                if (routeData != null) {
                    route = (IDictionary<string, object>)routeData.GetValue(dhc.Request);
                }
            }

            route.TryGetValue("controller", out path);
            route.TryGetValue("action", out action);

            // Inspect the context using provided policy rules
            IEnumerable<RulePolicy> effectivePolicies = rules.Policies(path.ToString(), action.ToString());

            if (context.User.Identity.IsAuthenticated) {

                var claimsId = context.User.Identities.Where(i => i.IsAuthenticated);
                var rules = effectivePolicies.Where(x => x.Authentication != AuthenticationStatus.NotAuthenticated);

                // For all authenticated identities, enumerate claims, evaluate against
                // rules for any matches.
                bool ruleResult = claimsId?.Any(id =>
                    rules.Any(r => {
                        var evaluation = r.EvaluatePrincipal(id);
                        if (evaluation) logger?.LogInformation($"Identity {id.Name} passed evaluation of policy: {r.Name}");

                        return evaluation;
                    }))
                    ?? false;
                return ruleResult;
            } else {

                var claimsId = context.User.Identities.Where(i => !i.IsAuthenticated);
                var rules = effectivePolicies.Where(x => x.Authentication != AuthenticationStatus.Authenticated);

                // For all authenticated identities, enumerate claims, evaluate against
                // rules for any matches.
                bool ruleResult = claimsId?.Any(id =>
                    rules.Any(r => {
                        var evaluation = r.EvaluatePrincipal(id);
                        if (evaluation) logger?.LogInformation($"Identity {id.Name} passed evaluation of policy: {r.Name}");

                        return evaluation;
                    }))
                    ?? false;
                return ruleResult;
            }
        }

    }
}
