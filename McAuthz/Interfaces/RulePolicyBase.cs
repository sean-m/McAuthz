using McRule;
using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Linq;
using System.Text;

namespace McAuthz.Interfaces {
    public class RulePolicyBase {

        internal List<IExpressionRule> policyRules = new List<IExpressionRule>();
        public Expression<Func<T, bool>>? GetExpression<T>() {
            return PredicateExpressionPolicyExtensions.CombineAnd(
                policyRules.Select(x => x.GetExpression<T>() ?? PredicateBuilder.False<T>()));
        }
    }
}
