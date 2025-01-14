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

            initExpression();
        }

        public string ClaimName { get; set; }
        public string ClaimValue { get; set; }

        public string? Key { get => ClaimName; }


        internal Func<Claim, bool> patternMatch;
        internal ExpressionRuleCollection? ExpressionRuleCollection { get; set; }
        internal void initExpression() {
            if (patternMatch != null) return;

            ExpressionRuleCollection = new ExpressionRuleCollection() {
                Rules = new[] {
                    new ExpressionRule(typeof(Claim).Name, "Type", ClaimName),
                    new ExpressionRule(typeof(Claim).Name, "Value", ClaimValue),
                    new ExpressionRule(typeof(Dictionary<string,string>).Name, ClaimName.ToLower(), ClaimValue)
                },
                TargetType = typeof(Claim).Name,
                RuleOperator = RuleOperator.And
            };

            patternMatch = ExpressionRuleCollection.GetPredicateExpression<Claim>().Compile();
        }

        private Dictionary<Type, dynamic> _cachedFunc = new Dictionary<Type, dynamic>();
        public Func<T, bool> BuildExpression<T>() {
            if (_cachedFunc.ContainsKey(typeof(T))) {
                return (Func<T,bool>)_cachedFunc[typeof(T)];
            }

            ExpressionRuleCollection = new ExpressionRuleCollection() {
                Rules = new[] {
                    new ExpressionRule(typeof(T).Name, ClaimName, ClaimValue),
                    new ExpressionRule(typeof(Dictionary<string,string>).Name, ClaimName.ToLower(), ClaimValue)
                },
                TargetType = typeof(Claim).Name,
                RuleOperator = RuleOperator.Or
            };

            var expression = ExpressionRuleCollection.GetPredicateExpression<T>() ?? PredicateBuilder.False<T>();
            _cachedFunc.Add(typeof(T), expression.Compile());
            return expression.Compile();
        }
    }
}
