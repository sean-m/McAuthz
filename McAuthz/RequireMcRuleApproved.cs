using McAuthz.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace McAuthz
{
    public class RequireMcRuleApproved : IAuthorizationRequirement {
        private Func<string, IEnumerable<RulePolicy>> _rules;

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
        public RequireMcRuleApproved(Func<string, IEnumerable<RulePolicy>> rules) {
            _rules = rules;
        }

        internal bool IsAuthorized(AuthorizationHandlerContext context) {
            var principal = context.User;

            string controller = "*";

            // Get controller from route data in context. The netstandard2.0 version
            // of DefaultHttpContext.Request doesn't have the RouteValues property
            // so we get it by reflection.
            // TODO refactor this into a more robust method with progressive fallback.
            IDictionary<string, object> route = new Dictionary<string, object>();
            if (context.Resource is DefaultHttpContext dhc) {
                Type dhcType = dhc.Request.GetType();
                var routeData = dhcType.GetProperties().FirstOrDefault(x => x.Name == "RouteValues");
                if (routeData != null) {
                    route = (IDictionary<string, object>)routeData.GetValue(dhc.Request);
                }
            }

            if (route.ContainsKey("controller")) {
                controller = route["controller"]?.ToString() ?? controller;
            }

            // Inspect the context using provided policy rules
            if (context.User.Identity.IsAuthenticated) {
                var claimsEvaluation = EvalateRulesOnClaims(context, controller);

                var responseEvaluation = EvaluateRulesOnResponseObject(context, controller);


                return claimsEvaluation && responseEvaluation;
            }

            return false;
        }

        private bool EvaluateRulesOnResponseObject(AuthorizationHandlerContext context, string controller) {

            var resource = context.Resource;

            // If you wanna look at nothing, be my guest
            if (resource == null) return true;

            var rules = _rules(controller);
            return rules.Any(x => x.EvaluateRules(resource));
        }

        private bool EvalateRulesOnClaims(AuthorizationHandlerContext context, string controller) {
            // Enumerate claims and evaluate rules on each one. Find any that match.
            var claimsId = context.User.Identities.Where(i => i.IsAuthenticated);
            var rules = _rules(controller);

            return claimsId.Any(id => {
                return rules.Any(x => x.EvaluateRules(id.Claims));
            });
        }
    }
}
