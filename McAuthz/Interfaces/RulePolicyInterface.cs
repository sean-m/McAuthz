﻿using McRule;
using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Text;

namespace McAuthz.Interfaces
{
    public interface RulePolicy : IExpressionRule
    {
        new string TargetType { get; set; }
        string Route { get; set; }
        bool EvaluateRules(object inputs);
        bool EvaluateRules(IEnumerable<object> inputs);

        public Expression<Func<T, bool>>? GetExpression<T>() {
            return PredicateExpressionPolicyExtensions.CombineAnd(
                policyRules.Select(x => x.GetExpression<T>() ?? PredicateBuilder.False<T>()));
        }

    }
}
