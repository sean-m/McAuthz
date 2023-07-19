using McAuthz.Interfaces;
using McRule;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Linq.Expressions;
using System.Security.Claims;
using System.Text;

namespace McAuthz.Policy
{
    public class ClaimRulePolicy : RulePolicy {

        #region properties
        public string TargetType { get => "Claim"; set => _ = value; }

        public string Route { get; set; } = "*";


        List<IExpressionRule> policyRules = new List<IExpressionRule>();

        #endregion  // properties


        #region constructor

        public ClaimRulePolicy() { }
            
        public ClaimRulePolicy(IEnumerable<(string, string)> ClaimMatches)
        {
            foreach (var claimMatch in ClaimMatches)
            {
                // Create a rule with two predicates to inspect a claim.
                // Claims denote the name of the claim in the Type property
                // and their value in the Value property, so both must match
                // for the rule to evaluate True.
                var rule = new ExpressionRuleCollection
                {
                    Rules = new List<ExpressionRule>() {
                            new ExpressionRule((TargetType, "Type", claimMatch.Item1)),
                            new ExpressionRule((TargetType, "Value", claimMatch.Item2))
                        },
                    RuleOperator = PredicateExpressionPolicyExtensions.RuleOperator.And
                };

                policyRules.Add(rule);
            }
        }

        #endregion  // constructor


        #region methods

        private Func<Claim, bool>? _rule;
        private string? _ruleString;
        public bool IdentityClaimsMatch(IEnumerable<Claim> claims)
        {
            if (_rule == null)
            {
                var ruleExpression = PredicateExpressionPolicyExtensions.CombineAnd(policyRules.Select(x => x.GetExpression<Claim>()));
                _ruleString = ruleExpression?.ToString();
                _rule = ruleExpression?.Compile();
            }
            if (_rule == null) return false;

            var policyResult = claims.Any(c => _rule.Invoke(c));

            System.Diagnostics.Trace.WriteLineIf(!string.IsNullOrEmpty(_ruleString), $"Policy rule '{_ruleString}' evaluated: {policyResult}");

            return policyResult;
        }


        #region IRulePolicy_IExpressionRule

        public Expression<Func<T, bool>>? GetExpression<T>() {
            return PredicateExpressionPolicyExtensions.CombineAnd(policyRules.Select(x => x.GetExpression<T>()));
        }

        public bool EvaluateRules(object input) {
            return EvaluateRules(new[] { input });
        }
        public bool EvaluateRules(IEnumerable<object> inputs) {
            if (inputs is IEnumerable<Claim> c) {
                return IdentityClaimsMatch(c);
            }
            return false;
        }

        #endregion  // IRulePolicy_IExpressionRule

        #endregion  // methods
    }
}
