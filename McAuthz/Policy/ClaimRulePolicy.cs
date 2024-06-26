﻿using McAuthz.Interfaces;
using McRule;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Data;
using System.Dynamic;
using System.Linq;
using System.Linq.Expressions;
using System.Security.Claims;
using System.Text;

namespace McAuthz.Policy
{
    public class ClaimRulePolicy : RulePolicyBase, RulePolicy {

        #region properties
        public string TargetType { get => "Claim"; set => _ = value; }

        public string Route { get; set; } = "*";

        public string Action { get; set; } = "GET";

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
                    RuleOperator = RuleOperator.And
                };

                // TODO benchmark this
                rule.GetPredicateExpression<Claim>(); // Prime expression tree cache

                Rules.Add(rule);
            }
        }

        #endregion  // constructor


        #region methods

        private Func<Claim, bool>? _rule;
        private string? _ruleString;
        public bool IdentityClaimsMatch(Claim claim)
        {
            if (_rule == null)
            {
                var ruleExpression = GetExpression<Claim>();
                _ruleString = ruleExpression?.ToString();
                _rule = ruleExpression?.Compile();
            }
            if (_rule == null) return false;

            var policyResult = _rule.Invoke(claim);

            System.Diagnostics.Debug.WriteLineIf(!string.IsNullOrEmpty(_ruleString), $"Policy rule '{_ruleString}' evaluated: {policyResult}");

            return policyResult;
        }


        #region RulePolicyInterface

        public bool EvaluateRules(dynamic input) {
            if (input is Claim c) {
                return IdentityClaimsMatch(c);
            }
            return false;
        }

        public bool EvaluateRules(IEnumerable<dynamic> inputs) {
            // Evaluate individual claims or lists of claims one at a time against the rule set
            if (inputs is Claim c) {
                return IdentityClaimsMatch(c);
            } else if (inputs is IEnumerable){
                try {
                    var claims = inputs.Where(x => x is Claim)?.Cast<Claim>();
                    if (claims == null) { return false; }
                    else { return claims.Any(c => IdentityClaimsMatch(c)); }
                }
                catch {
                    // FIXME Get logger and tell somebody about this.
                }
            }
            return false;
        }

        #endregion  // RulePolicyInterface
        #endregion  // methods
    }
}
