using McRule;
using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Linq;
using System.Text;

namespace McAuthz.Policy
{
    public class RulePolicyBase : IExpressionRule
    {

        public new string TargetType { get; set; }
        public string Route { get; set; }
        string IExpressionRule.TargetType { get => TargetType; set => TargetType = value; }

        internal List<IExpressionRule> policyRules = new List<IExpressionRule>();
        public Expression<Func<T, bool>>? GetExpression<T>()
        {
            return PredicateExpressionPolicyExtensions.CombineAnd(
                policyRules.Select(x => x.GetExpression<T>() ?? PredicateBuilder.False<T>()));
        }
    }
}
