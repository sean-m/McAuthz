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
                
                return claimsId.Any(id =>
                    _rules.Where(x => x.Route.Equals(context.Request.Path))
                        .Any(x => x.IdentityClaimsMatch(id.Claims)));
            }
            return false;
        }
    }
}
