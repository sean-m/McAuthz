using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using McAuthz.Policy;

namespace McAuthz.Interfaces {
    public interface RuleProviderInterface {
        IEnumerable<RulePolicy> Policies(string route, string action);
        IEnumerable<RulePolicy> Policies(string type);
        IEnumerable<FilterPolicy> Filters(string type, ClaimsIdentity identity);
    }
}
