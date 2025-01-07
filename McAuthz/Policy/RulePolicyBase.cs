using McRule;
using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Linq;
using System.Text;
using McAuthz.Requirements;
using McAuthz.Interfaces;
using System.Security.Claims;

namespace McAuthz.Policy {
    public class RulePolicyBase : RulePolicy {
        public RulePolicyBase() {
        }

        public string Name { get; set; }
        public new string TargetType { get; set; }
        public string Route { get; set; }
        public string Action { get; set; }
        public AuthenticationStatus Authentication { get; set; } = AuthenticationStatus.Authenticated;
        public List<Requirement> Requirements { get; set; } = new List<Requirement>();


        public Guid Id => throw new NotImplementedException();

        public virtual bool EvaluateRules(dynamic inputs) {
            return false;
        }

        public virtual bool EvaluateRules(ClaimsPrincipal inputs) {
            return false;
        }

        public new string ToString() => $"{Name} [{TargetType}] => /{Route}:{Action}";
    }
}
