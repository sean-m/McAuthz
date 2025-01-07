using McAuthz.Interfaces;
using McRule;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Security.Claims;
using System.Text;

namespace McAuthz.Policy
{
    public class ResourceRulePolicy : RulePolicyBase { }

    //public class ResourceRulePolicy<T> : ResourceRulePolicy, RulePolicy {

    //    public new string TargetType { get => typeof(T).Name; set => _ = value; }

    //    #region constructors

    //    public ResourceRulePolicy () { }

    //    public ResourceRulePolicy (IEnumerable<(string, string)> ResourceMatches) {
    //        foreach (var m in ResourceMatches) {
    //            Rules.Add(new ExpressionRule(TargetType, m.Item1, m.Item2));
    //        }
    //    }

    //    #endregion  constructors

    //    #region methods

    //    private Func<T, bool>? _rule;
    //    private string? _ruleString;
    //    public bool ResourceRuleMatches(dynamic Resource) {
    //        if (_rule == null) {
    //            var ruleExpression = GetExpression<T>();
    //            _ruleString = ruleExpression?.ToString();
    //            _rule = ruleExpression?.Compile();
    //        }
    //        if (_rule == null) return false;

    //        var policyResult = _rule.Invoke((T)Resource);

    //        System.Diagnostics.Trace.WriteLineIf(!string.IsNullOrEmpty(_ruleString), $"Policy rule '{_ruleString}' evaluated: {policyResult}");

    //        return policyResult;
    //    }

    //    #region RulePolicyInterface

    //    public bool EvaluateRules(dynamic inputs) {
    //        if (inputs is T input) {
    //            return ResourceRuleMatches(input);
    //        }
    //        return false;
    //    }

    //    public bool EvaluateRules(IEnumerable<dynamic> inputs) {
    //        return inputs.Where(x => x is T)?.Cast<T>()?.Any(x => ResourceRuleMatches(x)) ?? false;
    //    }

    //    #endregion  RulePolicyInterface
    //    #endregion  methods
    //}
}
