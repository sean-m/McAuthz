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
        public IEnumerable<Requirement> Requirements { get; set; } = new List<Requirement>();

        public IEnumerable<string?> Keys() {
            return Requirements.Select(r => r.Key);
        }

        public Func<T, bool> GetFunc<T>() {
            IEnumerable<PropertyRequirement> requirements = Requirements.Where(r => r is PropertyRequirement).Cast<PropertyRequirement>();

            var rules = requirements.Select(r => r.BuildExpression<T>());
            var combined = rules.Aggregate((a, b) => (x) => a(x) && b(x));
            return combined;
        }

        public Guid Id => throw new NotImplementedException();

        public virtual McAuthorizationResult EvaluateModel(dynamic inputs) {
            return new McAuthorizationResult { Succes = false };
        }
        public virtual McAuthorizationResult EvaluateModel<T>(dynamic inputs) {
            return new McAuthorizationResult { Succes = false };
        }
        public virtual McAuthorizationResult EvaluatePrincipal(dynamic inputs) {
            return new McAuthorizationResult { Succes = false };
        }
        public new string ToString() => $"{Name} [{TargetType}] => {Action?.ToUpper()} {Route}";
    }
}
