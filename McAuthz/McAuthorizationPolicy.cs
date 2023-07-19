using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Runtime.Serialization.Json;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace McAuthz {

    public class RequireMcRuleApprovedHandler : AuthorizationHandler<RequireMcRuleApproved> {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, RequireMcRuleApproved requirement) {
            if (requirement.IsAuthorized(context)) {
                context.Succeed(requirement);
            }

            return Task.CompletedTask;
        }
    }

    public class RequireMcRuleApproved : IAuthorizationRequirement {
        private Func<string, IEnumerable<ClaimRulePolicy>> _rules;

        public RequireMcRuleApproved(Func<string, IEnumerable<ClaimRulePolicy>> rules)
        {
            _rules = rules;
        }

        internal bool IsAuthorized(AuthorizationHandlerContext context) {
            var principal = context.User;
            
            string controller = "*";

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
            
            if (context.User.Identity.IsAuthenticated) {

                var claimsId = context.User.Identities.Where(i => i.IsAuthenticated);
                
                return claimsId.Any(id => {
                    var rules = _rules(controller);
                    return rules.Any(x => x.IdentityClaimsMatch(id.Claims));
                });
            }

            return false;
        }
    }
}
