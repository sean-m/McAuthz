using McRule;
using System;
using System.Collections.Generic;
using System.Text;

namespace McAuthz.Requirements {
    public class PropertyRequirement : PropertyMatchingBase, Requirement {
        public PropertyRequirement() { }
        public PropertyRequirement(string name, string value): base(name, value) { }

        public Func<Dictionary<string, string>, bool>? GetDictionaryFunc() {
            var expression = ExpressionRuleCollection.GetPredicateExpression<Dictionary<string, string>>();
            return expression?.Compile();
        }

        public Func<T, bool>? GetPropertyFunc<T>() {
            return ExpressionRuleCollection.GetPredicateExpression<T>()?.Compile();
        }
    }
}
