using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using McAuthz.Interfaces;
using McAuthz.Requirements;
using Microsoft.CodeAnalysis.Operations;

namespace McAuthz.Policy {
    public class FilterPolicy : RulePolicyBase, RulePolicy {
        public FilterPolicy() { }

        public FilterPolicy(string typeName) {
            TargetType = typeName;
        }

        public FilterPolicy(Type type) {
            TargetType = type.Name;
        }


        public IEnumerable<ClaimRequirement> ClaimRequirements =>
            Requirements.Where(r => r is ClaimRequirement).Cast<ClaimRequirement>();

        public IEnumerable<RoleRequirement> RoleRequirements =>
            Requirements.Where(r => r is RoleRequirement).Cast<RoleRequirement>();


        public bool AppliesToIdentity(ClaimsPrincipal principal) {
            return principal.Identities.All(i => AppliesToIdentity(i));
        }

        private bool PassesAuthenticationRequirements(ClaimsIdentity identity) {
            return Authentication switch {
                AuthenticationStatus.Authenticated => identity.IsAuthenticated,
                AuthenticationStatus.Unauthenticated => !identity.IsAuthenticated,
                _ => true
            };
        }

        public bool AppliesToIdentity(ClaimsIdentity principal) {
            var authenticatedEval = PassesAuthenticationRequirements(principal);

            var claimEval = ClaimRequirements.Count() > 0
                ? ClaimRequirements.All(x => principal.HasClaim(x.GetPredicate()))
                : true;

            var claimExprEval = true;

            var roleClaimeType = principal.RoleClaimType;
            var roleEval = RoleRequirements.Count() > 0
                ? RoleRequirements.All(x => principal.HasClaim(roleClaimeType, x.RoleName))
                : true;

            return authenticatedEval && claimEval && claimExprEval && roleEval;
        }

        private bool EvaluateOnClaim(Claim claim) {
            return ClaimRequirements.Any(x => x.EvaluateClaim(claim));
        }

        public Func<T, bool>? GetFunc<T>(ClaimsPrincipal identity) {
            if (AppliesToIdentity(identity)) {
                var propertyRequirements = Requirements.Where(r => r is PropertyRequirement).Cast<PropertyRequirement>();
                var rules = propertyRequirements.Select(r => r.BuildExpression<T>());
                return rules.Count() switch {
                    0 => null,
                    1 => rules.First(),
                    _ => rules.Aggregate((a, b) => (x) => a(x) && b(x))
                };
            }

            return null;
        }

        public Func<T, bool>? GetFunc<T>(ClaimsIdentity identity) {
            if (AppliesToIdentity(identity)) {
                var propertyRequirements = Requirements.Where(r => r is PropertyRequirement).Cast<PropertyRequirement>();
                var rules = propertyRequirements.Select(r => r.BuildExpression<T>());
                var combined = rules.Aggregate((a, b) => (x) => a(x) && b(x));
                return combined;
            }

            return null;
        }
    }

}