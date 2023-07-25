using System;
using System.Collections.Generic;
using System.Text;

namespace McAuthz.Interfaces {
    public interface RuleProviderInterface {
        IEnumerable<RulePolicy> Policies(string route);
        IEnumerable<RulePolicy> Policies(Type type);
    }
}
