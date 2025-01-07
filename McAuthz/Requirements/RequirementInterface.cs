using System;
using System.Collections.Generic;
using System.Text;

namespace McAuthz.Requirements {
    public interface Requirement {
        public Type ValueType { get; }
        public object GetValue();
    }
}
