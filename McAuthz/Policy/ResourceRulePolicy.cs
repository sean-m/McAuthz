using McAuthz.Interfaces;
using McAuthz.Requirements;
using McRule;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Reflection;
using System.Security.Claims;
using System.Text;

namespace McAuthz.Policy
{
    public class ResourceRulePolicy : RulePolicyBase, RulePolicy {

        #region properties

        #endregion  // properties

        #region constructors

        public ResourceRulePolicy() {  }

        public ResourceRulePolicy(IEnumerable<Requirement> Requirements) : base() {

            ((List<Requirement>)this.Requirements).AddRange(Requirements);
        }

        #endregion  // constructors

        #region methods

        private bool EvaluateModelList(IEnumerable<dynamic> models) {
            return models.All(x => MatchesRules(x));
        }
        private bool EvaluateModelList<T>(IEnumerable<T> models) {
            return models.All(x => MatchesRules<T>(x));
        }
        private bool MatchesRules(dynamic model) {

            IEnumerable<PropertyRequirement> requirements = Requirements.Where(r => r is PropertyRequirement).Cast<PropertyRequirement>();
            var result = requirements.All(rule => {
                if (model is Dictionary<string, string> dict) {
                    var func = rule.GetDictionaryFunc();
                    var result = func(dict);
                    return result;
                } else {
                    Type type = typeof(PropertyMatchingBase);
                    Type modelType = model.GetType();
                    MethodInfo method = type.GetMethod("BuildExpression");
                    MethodInfo genericMethod = method.MakeGenericMethod(modelType);
                    dynamic func = genericMethod.Invoke(rule, new object[] { });

                    var result = func(model);
                    return result;
                }
            });

            return result;
        }

        private bool MatchesRules<T>(T model) {

            IEnumerable<PropertyRequirement> requirements = Requirements.Where(r => r is PropertyRequirement).Cast<PropertyRequirement>();

            var rules = requirements.Select(r => r.BuildExpression<T>());
            var combined = rules.Aggregate((a, b) => (x) => a(x) && b(x));
            var result = combined(model);

            return result;
        }

        public override McAuthorizationResult EvaluateModel(dynamic inputs) {
            var result = new McAuthorizationResult { Succes=false };

            if (inputs is IEnumerable<dynamic> enumerable) {
                result.Succes = EvaluateModelList(enumerable);
            }

            result.Succes = MatchesRules(inputs);

            return result;
        }

        public override McAuthorizationResult EvaluateModel<T>(dynamic inputs) {
            var result = new McAuthorizationResult { Succes = false };

            if (inputs is IEnumerable<T> enumerable) {
                result.Succes = EvaluateModelList<T>(enumerable);
            }

            result.Succes = MatchesRules<T>(inputs);

            return result;
        }

        #endregion  // methods
    }

    public class ResourceRulePolicy<T> : ResourceRulePolicy, RulePolicy {

        public new string TargetType { get => typeof(T).Name; set => _ = value; }

        #region constructors

        public ResourceRulePolicy() { }

        public ResourceRulePolicy(IEnumerable<(string, string)> ResourceMatches) {
            var requirements = new List<Requirement>();
            foreach (var resourceMatch in ResourceMatches) {
                requirements.Add(new PropertyRequirement(resourceMatch.Item1, resourceMatch.Item2));
            }
            Requirements = requirements;
        }

        #endregion  constructors

        #region methods

        #endregion  methods
    }
}
