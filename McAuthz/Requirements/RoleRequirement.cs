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

        public string Key { get => RoleName; }

        public Type ValueType => throw new NotImplementedException();
    }
}
