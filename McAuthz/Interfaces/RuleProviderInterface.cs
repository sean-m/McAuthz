using System;
using System.Collections.Generic;
using System.Text;

namespace McAuthz.Interfaces {
    public interface RuleProviderInterface {
        IEnumerable<RulePolicy> Policies(string route, string action);
        IEnumerable<RulePolicy> Policies(string type);
    }
}
