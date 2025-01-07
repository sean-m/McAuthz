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
            get => base.TargetType ?? "ClaimSet";
            set {
                if (base.TargetType == null) { base.TargetType = value; } else { _ = value; }
            }
        }

        public IEnumerable<ClaimRequirement> ClaimRequirements { get => Requirements.Where(r => r is ClaimRequirement).Cast<ClaimRequirement>(); }
        public IEnumerable<ClaimExpression> ClaimExpressions { get => Requirements.Where(r => r is ClaimExpression).Cast<ClaimExpression>(); }
        public IEnumerable<RoleRequirement> RoleRequirements { get => Requirements.Where(r => r is RoleRequirement).Cast<RoleRequirement>(); }

        #endregion  // properties


        #region constructor

        public RequestPolicy() { init(); }

        public RequestPolicy(IEnumerable<Requirement> Requirements) {
            init();

            this.Requirements.AddRange(Requirements);
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

        #region RulePolicyInterface

        public new bool EvaluateRules(ClaimsPrincipal principal) {
            var claimEval = ClaimRequirements.Count() > 0 ? ClaimRequirements.All(x => principal.HasClaim(x.ClaimName, x.ClaimValue)) : true;

            var claimExprEval = true;

            var roleEval = RoleRequirements.Count() > 0 ? RoleRequirements.All(x => principal.IsInRole(x.RoleName)) : true;

            return claimEval && claimExprEval && roleEval;
        }

        public bool EvaluateRules(ClaimsIdentity principal) {
            var claimEval = ClaimRequirements.Count() > 0 ? ClaimRequirements.All(x => principal.HasClaim(x.ClaimName, x.ClaimValue)) : true;

            var claimExprEval = true;

            string roleClaimeType = principal.RoleClaimType;
            var roleEval = RoleRequirements.Count() > 0 ? RoleRequirements.All(x => principal.HasClaim(roleClaimeType, x.RoleName)) : true;

            return claimEval && claimExprEval && roleEval;
        }

        public bool EvaluateRules(dynamic inputs) {
            if (inputs == null) return false;

            if (inputs is ClaimsIdentity ci) return EvaluateRules(ci);

            if (inputs is ClaimsPrincipal cp) return EvaluateRules(cp);

            throw new NotImplementedException($"Not implemented for input type:{inputs?.GetType().Name}");
        }

        #endregion  // RulePolicyInterface
        #endregion  // methods

    }
}
