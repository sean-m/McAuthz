using System;
using System.Collections.Generic;
using System.Text;

namespace McAuthz.Interfaces {
    public interface RuleProviderInterface {
        IEnumerable<RulePolicy> Rules(string Route);
    }
}
