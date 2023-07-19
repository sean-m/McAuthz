using McRule;
using System;
using System.Collections.Generic;
using System.Text;

namespace McAuthz.Policy {
    public interface RulePolicy : IExpressionRule {
        new string TargetType { get; set; }
        string Route { get; set; }
        bool EvaluateRules(object inputs);
        bool EvaluateRules(IEnumerable<object> inputs);
    }
}
