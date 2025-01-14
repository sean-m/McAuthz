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
    public class ResourceRulePolicy : RequestPolicy, RulePolicy {

        #region properties

        #endregion  // properties

        #region constructors

        public ResourceRulePolicy() {  }

        public ResourceRulePolicy(IEnumerable<Requirement> Requirements) : base(Requirements) {

        }

        #endregion  // constructors

        #region methods

        private bool EvaluateModelList(IEnumerable<dynamic> models) {
            return models.All(x => MatchesRules(x));
        }

        private bool MatchesRules(dynamic model) {

            IEnumerable<PropertyRequirement> requirements = Requirements.Where(r => r is PropertyRequirement).Cast<PropertyRequirement>();
            return requirements.All(rule => {
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

            return false;
        }

        public override McAuthorizationResult EvaluateModel(dynamic inputs) {
            var result = new McAuthorizationResult { Succes=false };

            if (inputs is IEnumerable<dynamic> enumerable) {
                result.Succes = EvaluateModelList(enumerable);
            }

            result.Succes = MatchesRules(inputs);

            return result;
        }

        #endregion  // methods
    }

    public class ResourceRulePolicy<T> : ResourceRulePolicy, RulePolicy {

        public new string TargetType { get => typeof(T).Name; set => _ = value; }

        #region constructors

        public ResourceRulePolicy() { }

        public ResourceRulePolicy(IEnumerable<(string, string)> ResourceMatches) {

        }

        #endregion  constructors

        #region methods

        #endregion  methods
    }
}
