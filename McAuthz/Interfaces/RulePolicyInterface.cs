using McRule;
using System;
using System.Collections.Generic;
using System.Text;

namespace McAuthz.Interfaces {
    public interface RulePolicy {
        public string TargetType { get; set; }
        public string Route { get; set; }

        bool EvaluateRules(object inputs);
        bool EvaluateRules(IEnumerable<object> inputs);
    }
}
