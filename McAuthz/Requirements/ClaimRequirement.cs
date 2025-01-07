using System;
using System.Collections.Generic;
using System.Text;

namespace McAuthz.Requirements {
    public class ClaimRequirement : Requirement {
        public ClaimRequirement() { }

        public ClaimRequirement(string name, string value) {
            ClaimName = name;
            ClaimValue = value;
        }

        public string ClaimName { get; set; }
        public string ClaimValue { get; set; }

        public Type ValueType { get => typeof(KeyValuePair<string, string>); }
        public KeyValuePair<string, string> GetValue() =>
            new KeyValuePair<string, string> (ClaimName?.Trim(), ClaimValue?.Trim());

        object Requirement.GetValue() {
            return GetValue();
        }
    }
}
