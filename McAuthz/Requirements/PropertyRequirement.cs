using McRule;
using System;
using System.Collections.Generic;
using System.Text;

namespace McAuthz.Requirements {
    public class PropertyRequirement : PropertyMatchingBase, Requirement {
        public PropertyRequirement() { }
        public PropertyRequirement(string name, string value): base(name, value) { }

        public Func<Dictionary<string, string>, bool>? GetDictionaryFunc() {
            var expression = GetPropertyFunc<Dictionary<string, string>>();
            return expression;
        }

        public string? GetDictionaryFuncString() {
            return GetPropertyFuncString<Dictionary<string, string>>();
        }

        public Func<T, bool>? GetPropertyFunc<T>() {
            return BuildExpression<T>();
        }

        public string? GetPropertyFuncString<T>() {
            return BuildExpressionString<T>();
        }
    }
}
