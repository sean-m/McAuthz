using McAuthz.Requirements;
using McRule;
using Microsoft.AspNetCore.Authorization;
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
        public IEnumerable<Requirement> Requirements { get; set; }

        public IEnumerable<string?> Keys();
        McAuthorizationResult EvaluatePrincipal(dynamic inputs);
        McAuthorizationResult EvaluateModel(dynamic inputs);
    }
}
