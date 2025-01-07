using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Linq;
using System.Runtime;
using System.Text;

namespace McAuthz.Requirements {
    public class ExpressionRequirement : Requirement {
        public string Expression { get; set; }
        public string InputType { get; set; }
        public Type ValueType => throw new NotImplementedException();

        public Func<object, bool> GetValue() {
            throw new NotImplementedException();
        }


        object Requirement.GetValue() {
            return GetValue();
        }
    }
}
