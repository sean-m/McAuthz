using McAuthz.Policy;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml.Serialization;

namespace McAuthz
{
    public class PolicyRequestMapper {
        
        private ILogger<PolicyRequestMapper> _logger;
        private IEnumerable<ClaimRulePolicy> _rules;

        public PolicyRequestMapper(ILogger<PolicyRequestMapper> logger, IEnumerable<ClaimRulePolicy> rules)
        {
            _logger = logger;
            _rules = rules;
        }

        internal bool IsAuthorized(HttpContext context) {
            if (context.User.Identity.IsAuthenticated) {
                
                var claimsId = context.User.Identities.Where(i => i.IsAuthenticated);
                var rules = _rules.Where(x => x.Route.Equals(context.Request.Path));

                // For all authenticated identities, enumerate claims, evaluate against
                // rules for any matches.
                return claimsId?.Any(id =>
                    id.Claims.Any(claim => rules?.Any(rule => rule.IdentityClaimsMatch(claim)) 
                        ?? false))
                    ?? false;
            }

            return false;
        }
    }
}
