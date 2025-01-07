using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Linq;
using System.Runtime;
using System.Text;
using McRule;
using Newtonsoft.Json;

namespace McAuthz.Requirements {
    public class ExpressionRequirement : Requirement {
        public string ExpressionJson { get; set; }
        public string InputType { get; set; }
        public Type ValueType => throw new NotImplementedException();

        Expression<Func<dynamic, bool>> expression;
        public Func<object, bool> GetValue() {
            if (expression == null) {
                ExpressionRule rule = JsonConvert.DeserializeObject<ExpressionRule>(ExpressionJson);
                expression = rule.GetPredicateExpression<dynamic>();
            }
            return expression?.Compile() ?? PredicateBuilder.False<dynamic>().Compile();
        }

        object Requirement.GetValue() {
            return GetValue();
        }
    }
}
