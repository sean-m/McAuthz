using McRule;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;

namespace McAuthz.Requirements {
    public class ClaimRequirement : PropertyMatchingBase, Requirement {
        public ClaimRequirement() { }

        public ClaimRequirement(string name, string value) : base (name, value) {

        }


        public bool EvaluateClaim(Claim claim) {
            var rule = BuildExpression<Claim>();
            var result = rule(claim);
            return result;
        }

        public Predicate<Claim> GetPredicate() {
            var rule = BuildExpression<Claim>();
            Predicate<Claim> pred = (input) => rule(input);
            return pred;
        }
    }
}
