using McAuthz.Interfaces;
using McAuthz.Policy;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;

namespace McAuthz
{
    public class RequireMcRuleApproved : IAuthorizationRequirement {
        private RuleProviderInterface rules;
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

        internal (bool, string) IsAuthorized(AuthorizationHandlerContext context) {
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
            IEnumerable<RulePolicy> effectivePolicies = rules.Policies(path, action);

            bool principalRuleResult;

            if (context.User.Identity.IsAuthenticated) {

                var claimsId = context.User.Identities.Where(i => i.IsAuthenticated);
                var rules = effectivePolicies.Where(x => x.Authentication != AuthenticationStatus.NotAuthenticated);

                // For all authenticated identities, enumerate claims, evaluate against
                // rules for any matches.
                principalRuleResult = claimsId?.Any(id =>
                    rules.Any(r => {
                        var evaluation = r.EvaluatePrincipal(id);
                        if (evaluation.Succes) logger?.LogInformation($"Identity {id.Name} passed evaluation of policy: '{r.Name}'. {action} {path}");

                        return evaluation.Succes;
                    }))
                    ?? false;

                if (!principalRuleResult) {
                    logger?.LogWarning($"No policies authorized {action} {path}");
                    logger?.LogDebug($"Allow Authenticated RulePolicy: {{'Name':'Allow Authenticated {action.ToUpper()} to {path}','Route':'{path}','Action':'{action}','Authentication':'Authenticated'}}");
                }
            } else {
                logger?.LogDebug("User is unauthenticated!");

                var claimsId = context.User.Identities.Where(i => !i.IsAuthenticated);
                var rules = effectivePolicies.Where(x => x.Authentication != AuthenticationStatus.Authenticated);

                // For all authenticated identities, enumerate claims, evaluate against
                // rules for any matches.
                principalRuleResult = claimsId?.Any(id =>
                    rules.Any(r => {
                        var evaluation = r.EvaluatePrincipal(id);
                        if (evaluation.Succes) logger?.LogInformation($"Identity {id.Name} passed evaluation of policy: {r.Name}");

                        return evaluation.Succes;
                    }))
                    ?? false;

                if (!principalRuleResult) {
                    logger?.LogWarning($"No unauthenticated policies authorized {action} {path}");
                }
            }

            if (!principalRuleResult) logger?.LogDebug($"Allow Any RulePolicy: {{'Route':'{path}','Action':'{action}','Authentication':'Any'}}");

            return (principalRuleResult, string.Empty);
        }


        internal (bool, string) IsAuthorized(AuthorizationHandlerContext context, object model) {
            bool modelAuthorized = false;

            // Resolve data type
            if (model == null) return (false, "Value is null.");
            var type = model.GetType();
            string typeName = FigureOutPolicyType(type, model);

            // Inspect the context using provided policy rules
            IEnumerable<RulePolicy> effectivePolicies = rules.Policies(typeName);
            if (model is Dictionary<string, string> dict) {
                var caseInsensitive = new Dictionary<string, string>(dict, StringComparer.CurrentCultureIgnoreCase);
                modelAuthorized = EvaluateDictionary(caseInsensitive, typeName, effectivePolicies);
            }

            return (modelAuthorized, string.Empty);
        }

        private bool EvaluateDictionary(Dictionary<string,string> model, string typeName, IEnumerable<RulePolicy> effectivePolicies) {
            var requiredProperties
                = effectivePolicies.SelectMany(x => x.Keys());
            if (requiredProperties.Count() == 0) {
                logger?.LogWarning($"No policies resolved for type: '{typeName}'!");
                return false;
            }

            var results = effectivePolicies.Select(policy => new { policy = policy, result = policy.EvaluateModel(model) }).ToList();

            // Log out results of policy evaluation
            results.ForEach(p => {
                if (p.result.Succes) {
                    logger?.LogDebug($"Policy {p.policy.ToString()} {p.result.ToString()}");
                } else {
                    logger?.LogInformation($"Policy {p.policy.ToString()} {p.result.ToString()}");
                }
            });

            return results.All(r => r.result.Succes);
        }

        private string FigureOutPolicyType(Type type, object model) {
            string result = type.Name;

            if (result.Like("Dictionary`2")) {
                string maybeType = string.Empty;
                if (((Dictionary<string, string>)model).TryGetValue("#type", out maybeType)) {
                    result = maybeType;
                }
            }

            return result;
        }
    }
}
