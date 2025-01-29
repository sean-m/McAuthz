using McRule;
using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Security.Claims;
using System.Text;

namespace McAuthz.Requirements {
    public abstract class PropertyMatchingBase  {
        protected PropertyMatchingBase() {

        }
        protected PropertyMatchingBase(string name, string value) {
            ClaimName = name;
            ClaimValue = value;
        }

        public string ClaimName { get; set; }
        public string ClaimValue { get; set; }

        public string? Key { get => ClaimName; }

        private Dictionary<Type, dynamic> _cachedFunc = new Dictionary<Type, dynamic>();

        public ExpressionRuleCollection ExpressionRuleCollection { get; set; } = new ExpressionRuleCollection() {
            Rules = new List<IExpressionPolicy>()
        };

        public Func<T, bool> BuildExpression<T>() {
            if (_cachedFunc.ContainsKey(typeof(T))) {
                return (Func<T,bool>)_cachedFunc[typeof(T)];
            }
            if (typeof(T) == typeof(Claim)) {
                InitClaimExpression();
                return (Func<T, bool>)_cachedFunc[typeof(T)];
            }

            var expressionCollection = new ExpressionRuleCollection() {
                Rules = new[] {
                    new ExpressionRule(typeof(T).Name, ClaimName, ClaimValue),
                    new ExpressionRule(typeof(Dictionary<string,string>).Name, ClaimName.ToLower(), ClaimValue)
                },
                TargetType = typeof(T).Name,
                RuleOperator = RuleOperator.And
            };
            ((List<IExpressionPolicy>)ExpressionRuleCollection.Rules).Add(expressionCollection);

            var expression = expressionCollection.GetPredicateExpression<T>();
            _cachedFunc.Add(typeof(T), expression.Compile());
            return expression.Compile();
        }

        public string? BuildExpressionString<T>() {

            var expressionCollection = new ExpressionRuleCollection() {
                Rules = new[] {
                    new ExpressionRule(typeof(T).Name, ClaimName, ClaimValue),
                    new ExpressionRule(typeof(Dictionary<string,string>).Name, ClaimName.ToLower(), ClaimValue)
                },
                TargetType = typeof(T).Name,
                RuleOperator = RuleOperator.And
            };
            ((List<IExpressionPolicy>)ExpressionRuleCollection.Rules).Add(expressionCollection);

            var expression = expressionCollection.GetPredicateExpression<T>();
            return expression?.ToString();
        }

        /// <summary>
        /// Intializes a custom pattern match for the Claim type. Where a rule is generally intended to match
        /// on a given member field, what would specify the member name should match ClaimName and the value
        /// should match ClaimValue so this tries to build a rule that matches an operator's intent.
        /// </summary>
        private void InitClaimExpression() {
            var expressionCollection = new ExpressionRuleCollection() {
                Rules = new[] {
                    new ExpressionRule(typeof(Claim).Name, "Type", ClaimName),
                    new ExpressionRule(typeof(Claim).Name, "Value", ClaimValue),
                },
                TargetType = typeof(Claim).Name,
                RuleOperator = RuleOperator.And
            };
            ((List<IExpressionPolicy>)ExpressionRuleCollection.Rules).Add(expressionCollection);
            var expression = expressionCollection.GetPredicateExpression<Claim>();
            _cachedFunc.Add(typeof(Claim), expression.Compile());
        }
    }
}
