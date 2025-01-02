using McAuthz.Interfaces;
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
        public new string TargetType {
            get => base.TargetType ?? "ClaimSet";
            set {
                if (base.TargetType == null) { base.TargetType = value; }
                else { _ = value; }
            }
        }
        #endregion  // properties


        #region constructor

        public ClaimRulePolicy() { init(); }

        public ClaimRulePolicy(IEnumerable<(string, string)> ClaimMatches)
        {
            init();

            // Create a rule with two predicates to inspect a claim.
            // Claims denote the name of the claim in the Type property
            // and their value in the Value property, so both must match
            // for the rule to evaluate True.
            var rule = new ExpressionPolicy {
                Rules = ClaimMatches.Select(x => new ExpressionRule((TargetType, x.Item1, x.Item2))).ToList(),
                RuleOperator = RuleOperator.And
            };

            // TODO benchmark this
            rule.GetPredicateExpression<ClaimSet>(); // Prime expression tree cache

            Rules.Add(rule);
        }

        private void init() {
            Route = "*";
            Action = "GET";
            TargetType = "ClaimSet";
        }

        #endregion  // constructor


        #region methods

        private Func<ClaimSet, bool>? _ruleSet;
        private string? _ruleString;
        internal bool IdentityClaimsMatch(Claim claim)
        {
            var claimSet = new ClaimSet(new[] { claim });
            if (_ruleSet == null)
            {
                var ruleExpression = GetExpression<ClaimSet>();
                _ruleString = ruleExpression?.ToString();
                _ruleSet = ruleExpression?.Compile();
            }
            if (_ruleSet == null) return false;

            var policyResult = _ruleSet.Invoke(claimSet);

            System.Diagnostics.Debug.WriteLineIf(!string.IsNullOrEmpty(_ruleString), $"Policy rule '{_ruleString}' evaluated: {policyResult}");

            return policyResult;
        }

        internal bool IdentityClaimsMatch(ClaimSet claim) {
            if (_ruleSet == null) {
                var ruleExpression = GetExpression<ClaimSet>();
                _ruleString = ruleExpression?.ToString();
                _ruleSet = ruleExpression?.Compile();
            }
            if (_ruleSet == null) return false;

            var policyResult = _ruleSet.Invoke(claim);

            System.Diagnostics.Debug.WriteLineIf(!string.IsNullOrEmpty(_ruleString), $"Policy rule '{_ruleString}' evaluated: {policyResult}");

            return policyResult;
        }

        #region RulePolicyInterface

        public bool EvaluateRules(dynamic inputs) {
            // Evaluate individual claims or lists of claims one at a time against the rule set
            var result = false;
            if (inputs is Claim c) {
                result = IdentityClaimsMatch(c);
            } else if (inputs is IEnumerable<dynamic> en){
                try {

                    var claims = Enumerable.Where(en, x => x is Claim)?.Cast<Claim>();
                    var claimSet = new ClaimSet(claims);
                    if (claims == null) {
                        // TODO LOG no claims given as inputs, denied
                        return false;
                    }
                    else {
                        result = IdentityClaimsMatch(claimSet);
                    }
                }
                catch {
                    // FIXME Get logger and tell somebody about this.
                }
            }
            return result;
        }

        #endregion  // RulePolicyInterface
        #endregion  // methods


        internal class ClaimSet : Dictionary<string, List<string>> {

            public ClaimSet() { }
            public ClaimSet(IEnumerable<Claim> claims) {
                foreach (Claim claim in claims) {
                    SafeAdd(claim.Type, claim.Value);
                }
            }

            private void SafeAdd(string key, List<string> value) {
                if (this.ContainsKey(key)) {
                    this[key].Concat(value);
                } else {
                    Add(key, value);
                }
            }

            private void SafeAdd(string key, string value) {
                if (this.ContainsKey(key)) {
                    this[key].Concat(new[] { value });
                } else {
                    Add(key, new[] { value }.ToList());
                }
            }
        }
    }
}
