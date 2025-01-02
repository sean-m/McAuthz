using McAuthz.Interfaces;
using McAuthz.Policy;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace McAuthz
{
    public class RequireMcRuleApproved : IAuthorizationRequirement {
        private RuleProviderInterface  _rules;

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
        public RequireMcRuleApproved(RuleProviderInterface rules) {
            _rules = rules;
        }

        internal bool IsAuthorized(AuthorizationHandlerContext context) {
            var principal = context.User;

            dynamic controller = "*";
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

            route.TryGetValue("controller", out controller);
            route.TryGetValue("action", out action);

            // Inspect the context using provided policy rules
            if (context.User.Identity.IsAuthenticated) {
                bool clamsEvaluation = false;
                clamsEvaluation = EvalateRulesOnClaims(context, controller.ToString(), action.ToString());

                return clamsEvaluation;
            }

            return false;
        }

        private bool EvalateRulesOnClaims(AuthorizationHandlerContext context, string route, string action) {
            // Enumerate claims and evaluate rules on each one. Find any that match.
            var claimsId = context.User.Identities.Where(i => i.IsAuthenticated);
            var rules = _rules.Policies(route, action)?.Where(x => x is ClaimRulePolicy);

            var result =  claimsId?.Any(id => { // For all authenticated identities
                return rules?.Any(x => x.EvaluateRules(id.Claims)) ?? false;
            }) ?? false;

            return result;
        }
    }
}
