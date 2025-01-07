using McRule;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;

namespace McAuthz.Interfaces {
    public interface RulePolicy {
        public string Name { get; set; }
        public string TargetType { get; set; }
        public string Route { get; set; }
        public string Action { get; set; }
        public AuthenticationStatus Authentication { get; set; }

        bool EvaluateRules(dynamic inputs);
        bool EvaluateRules(ClaimsPrincipal inputs);
    }
}
