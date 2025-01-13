using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Linq;
using System.Runtime;
using System.Text;
using RulesEngine.Models;

namespace McAuthz {

    public static class ExpressionGenerator {


        public static class H {
            public static bool DictionaryValueEquals(IDictionary<string, string> Dict, string Key, string Value) {
                return Dict.ContainsKey(Key) && Dict["Key"] == Value;
            }

            public static string Switch(string operand, params string[] options) {
                var result = options.Select((element, i) => new { element, i })
                    .GroupBy(x => x.i / 2)
                    .Select(x => new { option = x.ElementAt(0).element, value = x.ElementAt(1).element })
                    .FirstOrDefault(x =>
                        String.Equals(operand, x.option));

                if (result != null) {
                    return result.value.ToString();
                }

                return operand;
            }
        }

        public static Expression<Func<dynamic, string>> Parse(Type sourceType, string expression, string targetAttr = null) {
            string expressionStr = expression;

            if (string.IsNullOrWhiteSpace(expression)) return null;

            if (string.IsNullOrWhiteSpace(targetAttr) && expression.ToLower() == "eq") return null;

            if (expression.ToLower() == "eq") {
                expressionStr = $"src.{targetAttr} == null ? String.Empty : src.{targetAttr}.ToString()";
            }

            var srcParam = Expression.Parameter(sourceType, "src");

            var expressionParameters = new[] { srcParam };


            var reSettings = new ReSettings {
                CustomTypes = new Type[] { typeof(H), sourceType }
            };
            var parser = new RulesEngine.ExpressionBuilders.RuleExpressionParser(reSettings);

            var exp = parser.Parse(expressionStr, expressionParameters, typeof(string));
            var expFunc = Expression.Lambda<Func<dynamic, string>>(exp, false, expressionParameters);
            return expFunc;
        }

        public static Expression<Func<T1, string>> Parse<T1>(string expression, string targetAttr = null) {
            string expressionStr = expression;

            if (string.IsNullOrWhiteSpace(expression)) return null;

            if (string.IsNullOrWhiteSpace(targetAttr) && expression.ToLower() == "eq") return null;

            if (expression.ToLower() == "eq") {
                expressionStr = $"src.{targetAttr} == null ? String.Empty : src.{targetAttr}.ToString()";
            }

            var srcParam = Expression.Parameter(typeof(T1), "src");

            var expressionParameters = new[] { srcParam };


            var reSettings = new ReSettings {
                CustomTypes = new Type[] { typeof(H), typeof(T1) }
            };
            var parser = new RulesEngine.ExpressionBuilders.RuleExpressionParser(reSettings);

            var exp = parser.Parse(expressionStr, expressionParameters, typeof(string));
            var expFunc = Expression.Lambda<Func<T1, string>>(exp, false, expressionParameters);
            return expFunc;
        }

        public static Expression<Func<dynamic, bool>> ParsePredicate(Type sourceType, string expression) {
            string expressionStr = expression;

            if (string.IsNullOrWhiteSpace(expression)) return null;

            var srcParam = Expression.Parameter(sourceType, "src");

            var expressionParameters = new[] { srcParam };


            var reSettings = new ReSettings {
                CustomTypes = new Type[] { typeof(H), sourceType }
            };
            var parser = new RulesEngine.ExpressionBuilders.RuleExpressionParser(reSettings);

            var exp = parser.Parse(expressionStr, expressionParameters, typeof(string));
            var expFunc = Expression.Lambda<Func<dynamic, bool>>(exp, false, expressionParameters);
            return expFunc;
        }

        public static Expression<Func<T1, bool>> ParsePredicate<T1>(string expression) {
            string expressionStr = expression;

            if (string.IsNullOrWhiteSpace(expression)) return null;

            var srcParam = Expression.Parameter(typeof(T1), "src");

            var expressionParameters = new[] { srcParam };


            var reSettings = new ReSettings {
                CustomTypes = new Type[] { typeof(H), typeof(T1) }
            };
            var parser = new RulesEngine.ExpressionBuilders.RuleExpressionParser(reSettings);

            var exp = parser.Parse(expressionStr, expressionParameters, typeof(string));
            var expFunc = Expression.Lambda<Func<T1, bool>>(exp, false, expressionParameters);
            return expFunc;
        }

        private static Dictionary<Type, Dictionary<string, Expression>> propertySelectors;


        public static dynamic GetSelectorForType(Type selectType, string selectorType) {

            return propertySelectors[selectType][selectorType.ToLower()];
        }

        private static Type ByName(string name) {
            // Didn't have time to do this myself (I've got code lying around somewhere for this.
            // Got it from here: https://stackoverflow.com/questions/20008503/get-type-by-name
            return
                AppDomain.CurrentDomain.GetAssemblies()
                    .Reverse()
                    .Select(assembly => assembly.GetType(name))
                    .FirstOrDefault(t => t != null)
                // Safely delete the following part
                // if you do not want fall back to first partial result
                ??
                AppDomain.CurrentDomain.GetAssemblies()
                    .Reverse()
                    .SelectMany(assembly => assembly.GetTypes())
                    .FirstOrDefault(t => t.Name.Contains(name));
        }
    }

}
