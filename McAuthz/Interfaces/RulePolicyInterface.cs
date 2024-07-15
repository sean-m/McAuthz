using McRule;
using System;
using System.Collections.Generic;
using System.Text;

namespace McAuthz.Interfaces {
    public interface RulePolicy {
        public string TargetType { get; set; }
        public string Route { get; set; }
        public string Action { get; set; }

        bool EvaluateRules(dynamic inputs);
    }
}
