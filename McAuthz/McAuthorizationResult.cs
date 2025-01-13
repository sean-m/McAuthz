using System;
using System.Collections.Generic;
using System.Text;

namespace McAuthz {
    public class McAuthorizationResult {
        public bool Succes { get; set; }
        public Exception? Exception { get; set; }
        public string? FailureReason { get; set; }
        public DateTime EvaluationTime { get; set; } = DateTime.Now;

        public override string ToString() {
            if (Succes) {
                return EvaluationTime.ToString() + " Success";
            }

            return EvaluationTime.ToString() + " Failure " + FailureReason;
        }
    }
}
