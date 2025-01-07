using McAuthz.Interfaces;
using McAuthz.Policy;
using Microsoft.AspNetCore.Http;
using Microsoft.CodeAnalysis.Elfie.Diagnostics;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml.Serialization;

namespace McAuthz
{
    public class PolicyRequestMapper {

        private ILogger<PolicyRequestMapper> logger;
        private RuleProviderInterface rules;

        public PolicyRequestMapper(ILogger<PolicyRequestMapper> logger, RuleProviderInterface rules)
        {
            this.logger = logger;
            this.rules = rules;
        }

        internal bool IsAuthorized(HttpContext context) {
            // Inspect the context using provided policy rules
            string path = context.Request.Path;
            string action = context.Request.Method;
            IEnumerable<RulePolicy> effectivePolicies = rules.Policies(path, action);

            bool ruleResult;

            if (context.User.Identity.IsAuthenticated) {

                var claimsId = context.User.Identities.Where(i => i.IsAuthenticated);
                var rules = effectivePolicies.Where(x => x.Authentication != AuthenticationStatus.NotAuthenticated);

                // For all authenticated identities, enumerate claims, evaluate against
                // rules for any matches.
                ruleResult = claimsId?.Any(id =>
                    rules.Any(r => {
                        var evaluation = r.EvaluateRules(id);
                        if (evaluation) logger?.LogInformation($"Identity {id.Name} passed evaluation of policy: {r.Name}");

                        return evaluation;
                    }))
                    ?? false;

                if (!ruleResult) { logger?.LogWarning($"No policies authorized {action} {path}"); }
            } else {

                var claimsId = context.User.Identities.Where(i => !i.IsAuthenticated);
                var rules = effectivePolicies.Where(x => x.Authentication != AuthenticationStatus.Authenticated);

                // For all authenticated identities, enumerate claims, evaluate against
                // rules for any matches.
                ruleResult = claimsId?.Any(id =>
                    rules.Any(r => {
                        var evaluation = r.EvaluateRules(id);
                        if (evaluation) logger?.LogInformation($"Identity {id.Name} passed evaluation of policy: {r.Name}");

                        return evaluation;
                    }))
                    ?? false;

                if (!ruleResult) { logger?.LogWarning($"No unauthenticated policies authorized {action} {path}"); }
            }

            return ruleResult;
        }
    }
}
