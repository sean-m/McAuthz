using McAuthz.Interfaces;
using McAuthz.Requirements;
using McRule;
using Newtonsoft.Json;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Data;
using System.Dynamic;
using System.Linq;
using System.Linq.Expressions;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace McAuthz.Policy {
    public class RequestPolicy : RulePolicyBase, RulePolicy {

        #region properties

        public new string TargetType {
            get; set;
        } = "ClaimSet";

        public IEnumerable<ClaimRequirement> ClaimRequirements { get => Requirements.Where(r => r is ClaimRequirement).Cast<ClaimRequirement>(); }

        public IEnumerable<RoleRequirement> RoleRequirements { get => Requirements.Where(r => r is RoleRequirement).Cast<RoleRequirement>(); }

#endregion  // properties


        #region constructor

        public RequestPolicy() { init(); }

        public RequestPolicy(IEnumerable<Requirement> Requirements) {
            init();

            ((List<Requirement>)this.Requirements).AddRange(Requirements);
        }

        private void init() {
            Route = "*";
            Action = "GET";
            TargetType = "ClaimSet";
        }


        #endregion  // constructor


        #region methods

        public static RequestPolicy FromJson(string Input) {
            var result = new RequestPolicy();
            var json = JsonConvert.DeserializeObject<Dictionary<string,object>>(Input);

            foreach (var key in json.Keys) {
                if (key.Like("name")) {
                    result.Name = json[key]?.ToString();
                    continue;
                }
                if (key.Like("route")) {
                    result.Route = json[key]?.ToString();
                    continue;
                }
                if (key.Like("action")) {
                    result.Action = json[key]?.ToString();
                    continue;
                }
                if (key.Like("authentication")) {
                    object stat;
                    if (Enum.TryParse(typeof(AuthenticationStatus), json[key]?.ToString(), out stat)) {
                        result.Authentication = (AuthenticationStatus)stat;
                    } else {
                        Console.WriteLine($"Error parsing the 'authentication' key on a json record. Failed key value: '{json[key]}'");
                    }
                }
            }

            return result;
        }

        #region inspectPrincipal

        private  bool EvaluatePrincipal(ClaimsPrincipal principal) {
            var claimEval = !ClaimRequirements.Any() || ClaimRequirements.All(x => principal.HasClaim(x.GetPredicate()));

            var roleEval = !RoleRequirements.Any() || RoleRequirements.All(x => principal.IsInRole(x.RoleName));

            return claimEval && roleEval;
        }

        private bool EvaluatePrincipal(ClaimsIdentity principal) {
            var claimEval = !ClaimRequirements.Any() || ClaimRequirements.All(x => principal.HasClaim(x.GetPredicate()));

            string roleClaimType = principal.RoleClaimType;
            var roleEval = !RoleRequirements.Any() || RoleRequirements.All(x => principal.HasClaim(roleClaimType, x.RoleName));

            return claimEval && roleEval;
        }

        private bool EvaluateOnClaim(Claim claim) {
            return ClaimRequirements.Any(x => x.EvaluateClaim(claim));
        }

        private bool EvaluateListOfClaims(List<Claim> claims) {

            var claimEval = !ClaimRequirements.Any() || claims.All(EvaluateOnClaim);

            return claimEval;
        }

        public override McAuthorizationResult EvaluatePrincipal(dynamic inputs) {
            var evaluateSuccess = new McAuthorizationResult {
                Succes = false
            };
            if (inputs == null) {
                evaluateSuccess.FailureReason = "Principal cannot be null";
                return evaluateSuccess;
            }

            try {
                evaluateSuccess.Succes = inputs switch {
                    ClaimsIdentity ci => EvaluatePrincipal(ci),
                    ClaimsPrincipal cp => EvaluatePrincipal(cp),
                    IEnumerable<Claim> lc => EvaluateListOfClaims(lc.ToList()),
                    Claim c => EvaluateOnClaim(c),
                    _ => throw new NotImplementedException($"Not implemented for input type:{inputs?.GetType().Name}"),
                };
            } catch (Exception e) {
                evaluateSuccess.Exception = e;
                evaluateSuccess.FailureReason = e.ToString();
            }

            return evaluateSuccess;
        }

        #endregion  // inspectPrincipal

        #endregion  // methods

    }
}
