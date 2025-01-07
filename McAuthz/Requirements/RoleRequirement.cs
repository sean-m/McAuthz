using System;
using System.Collections.Generic;
using System.Text;

namespace McAuthz.Requirements {
    public class RoleRequirement : Requirement {
        public RoleRequirement() { }

        public RoleRequirement(string role) {
            RoleName = role;
        }

        public string RoleName { get; set; }

        public Type ValueType => throw new NotImplementedException();

        public string GetValue() => RoleName?.Trim();

        object Requirement.GetValue() {
            return GetValue();
        }
    }
}
