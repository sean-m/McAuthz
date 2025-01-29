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
                        // TODO log this
                    }
                    continue;
                }
            }

            return result;
        }

        #region inspectPrincipal

        private  bool EvaluatePrincipal(ClaimsPrincipal principal) {
            var claimEval = ClaimRequirements.Count() > 0 ? ClaimRequirements.All(x => principal.HasClaim(x.GetPredicate())) : true;

            var claimExprEval = true;

            var roleEval = RoleRequirements.Count() > 0 ? RoleRequirements.All(x => principal.IsInRole(x.RoleName)) : true;

            return claimEval && claimExprEval && roleEval;
        }

        private bool EvaluatePrincipal(ClaimsIdentity principal) {
            var claimEval = ClaimRequirements.Count() > 0 ? ClaimRequirements.All(x => principal.HasClaim(x.GetPredicate())) : true;

            var claimExprEval = true;

            string roleClaimeType = principal.RoleClaimType;
            var roleEval = RoleRequirements.Count() > 0 ? RoleRequirements.All(x => principal.HasClaim(roleClaimeType, x.RoleName)) : true;

            return claimEval && claimExprEval && roleEval;
        }

        private bool EvaluateOnClaim(Claim claim) {
            return ClaimRequirements.Any(x => x.EvaluateClaim(claim));
        }

        private bool EvaluateListOfClaims(List<Claim> lc) {

            var claimEval = ClaimRequirements.Count() > 0
                ? lc.All(claim => EvaluateOnClaim(claim))
                : true;

            return claimEval;
        }

        public override McAuthorizationResult EvaluatePrincipal(dynamic inputs) {
            var evaluateSucces = new McAuthorizationResult {
                Succes = false
            };
            if (inputs == null) {
                evaluateSucces.FailureReason = "Principal cannot be null";
                return evaluateSucces;
            }

            try {
                evaluateSucces.Succes = inputs switch {
                    ClaimsIdentity ci => EvaluatePrincipal(ci),
                    ClaimsPrincipal cp => EvaluatePrincipal(cp),
                    IEnumerable<Claim> lc => EvaluateListOfClaims(lc.ToList()),
                    Claim c => EvaluateOnClaim(c),
                    _ => throw new NotImplementedException($"Not implemented for input type:{inputs?.GetType().Name}"),
                };
            } catch (Exception e) {
                evaluateSucces.Exception = e;
                evaluateSucces.FailureReason = e.ToString();
            }

            return evaluateSucces;
        }

        #endregion  // inspectPrincipal

        #endregion  // methods

    }
}
