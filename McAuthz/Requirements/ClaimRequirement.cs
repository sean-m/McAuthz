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
            initExpression();

            var result = patternMatch(claim);
            return result;
        }

        public Predicate<Claim> GetPredicate() {
            initExpression();
            Predicate<Claim> pred = (input) => patternMatch(input);
            return pred;
        }
    }
}
