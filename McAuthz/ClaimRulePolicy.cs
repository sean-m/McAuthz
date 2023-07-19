using McRule;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Linq.Expressions;
using System.Security.Claims;
using System.Text;

namespace McAuthz {
    public class ClaimRulePolicy : IExpressionRule {

        public string TargetType { get => "Claim"; set => _ = value; }

        string IExpressionRule.TargetType { get => TargetType; set => TargetType = value; }

        private Func<Claim, bool> _rule;
        private string _ruleString;

        List<IExpressionRule> policyRules = new List<IExpressionRule>();

        public ClaimRulePolicy() { }

        public ClaimRulePolicy(IEnumerable<(string, string)> ClaimMatches) {
            
            foreach (var claimMatch in ClaimMatches) {
                var rule = new ExpressionRuleCollection {
                    Rules = new List<ExpressionRule>() {
                            new ExpressionRule((TargetType, "Type", claimMatch.Item1)),
                            new ExpressionRule((TargetType, "Value", claimMatch.Item2))
                        },
                    RuleOperator = PredicateExpressionPolicyExtensions.RuleOperator.And
                };

                policyRules.Add(rule);
            }
        }

        public string Route { get; set; }

        public bool IdentityClaimsMatch(IEnumerable<Claim> claims) {

            if (_rule == null) {
                var compiledRules = PredicateExpressionPolicyExtensions.CombineAnd(policyRules.Select(x => x.GetExpression<Claim>()));
                _ruleString = compiledRules.ToString();
                _rule = compiledRules.Compile();
            }
            if (_rule == null) return false;

            var policyResult = claims.Any(c =>  _rule.Invoke(c));

            System.Diagnostics.Trace.WriteLineIf(!string.IsNullOrEmpty(_ruleString), $"Policy rule '{_ruleString}' evaluated: {policyResult}");

            return policyResult;
        }

        public Expression<Func<T, bool>>? GetExpression<T>() {
            throw new NotImplementedException();
        }
    }
}
