using McAuthz.Policy;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.CodeAnalysis.CSharp.Syntax;
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
    public class RequireMcRuleApprovedHandler : AuthorizationHandler<McRuleApprovedRequirement> {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, McRuleApprovedRequirement requirement) {

            var authorized = context.Resource == null
                ? requirement.IsAuthorized(context)
                : requirement.IsAuthorized(context, context.Resource); // This is for authorizing based on identity and the model passed to the controller. There's no route and path info in this context object.
            if (authorized.Item1) {
                context.Succeed(requirement);
            } else {
                context.Fail(new AuthorizationFailureReason(this, authorized.Item2));
            }

            return Task.CompletedTask;
        }
    }
}
