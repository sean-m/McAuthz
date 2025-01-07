using McRule;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;

namespace McAuthz.Requirements {
    public class ClaimRequirement : Requirement {
        public ClaimRequirement() { }

        public ClaimRequirement(string name, string value) {
            ClaimName = name;
            ClaimValue = value;

        }

        public string ClaimName { get; set; }
        public string ClaimValue { get; set; }

        public Type ValueType { get => typeof(KeyValuePair<string, string>); }
        public KeyValuePair<string, string> GetValue() =>
            new KeyValuePair<string, string> (ClaimName?.Trim(), ClaimValue?.Trim());

        object Requirement.GetValue() {
            return GetValue();
        }

        void initExpression() {
            if (patternMatch != null) return;

            var expr = new ExpressionRuleCollection() {
                Rules = new[] {
                    new ExpressionRule(typeof(Claim).Name, "Type", ClaimName),
                    new ExpressionRule(typeof(Claim).Name, "Value", ClaimValue)
                },
                TargetType = typeof(Claim).Name,
                RuleOperator = RuleOperator.And
            };

            patternMatch = expr.GetPredicateExpression<Claim>().Compile();
        }

        Func<Claim, bool> patternMatch;
        public bool EvaluateClaim(Claim claim) {
            initExpression();

            var result = patternMatch(claim);
            return result;
        }

        public Predicate<Claim> GetPredicate() {
            initExpression();
            // TODO return predicate from this since ClaimsIdentity.HasClaim can take a predicate and will make use of our fancy pattern matching
            return null;
        }
    }
}
