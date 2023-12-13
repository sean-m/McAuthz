using McAuthz.Interfaces;
using System;
using System.Collections.Generic;
using System.Text;

namespace McAuthz.Policy {
    public class ClaimPrincipalRulePolicy : RulePolicyBase, RulePolicy {

        #region constructors

        public ClaimPrincipalRulePolicy() { }



        #endregion  constructors


        #region methods



        #region RulePolicyInterface

        public bool EvaluateRules(dynamic inputs) {
            throw new NotImplementedException();
        }

        public bool EvaluateRules(IEnumerable<dynamic> inputs) {
            throw new NotImplementedException();
        }

        #endregion  RulePolicyInterface
        #endregion  methods
    }
}
