using McAuthz.Policy;
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

namespace McAuthz
{
    public class RequireMcRuleApprovedHandler : AuthorizationHandler<RequireMcRuleApproved> {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, RequireMcRuleApproved requirement) {
            if (requirement.IsAuthorized(context)) {
                context.Succeed(requirement);
            }

            return Task.CompletedTask;
        }
    }
}
