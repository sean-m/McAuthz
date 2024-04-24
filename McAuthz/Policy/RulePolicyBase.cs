using McRule;
using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Linq;
using System.Text;

namespace McAuthz.Policy
{
    public class RulePolicyBase : IExpressionRuleCollection
    {

        public new string TargetType { get; set; }
        public string Route { get; set; }

        public string Action { get; set; }

        public Guid Id => throw new NotImplementedException();


        public RuleOperator RuleOperator => throw new NotImplementedException();

        IEnumerable<IExpressionPolicy> IExpressionRuleCollection.Rules => Rules;

        IDictionary<string, string[]> IExpressionRuleCollection.Properties => throw new NotImplementedException();

        public List<IExpressionPolicy> Rules = new List<IExpressionPolicy>();
        public Expression<Func<T, bool>>? GetExpression<T>()
        {
            var generator = PredicateExpressionPolicyExtensions.GetCoreExpressionGenerator();
            return PredicateExpressionPolicyExtensions.CombineAnd(
                Rules.Select(x => x.GetPredicateExpression<T>() ?? PredicateBuilder.False<T>()));
        }
    }
}
