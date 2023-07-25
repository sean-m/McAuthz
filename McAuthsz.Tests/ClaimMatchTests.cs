using McAuthz.Policy;
using System.Security.Claims;

namespace McAuthsz.Tests {
    public class ClaimMatchTests {

        ClaimRulePolicy matchSean = new ClaimRulePolicy(
            new[] { ("name", "Sean McArdle") }) {
            Route = "/api/User"
        };

        ClaimRulePolicy matchNotSean = new ClaimRulePolicy(
           new[] { ("name", "!Sean McArdle") }) {
            Route = "/api/User"
        };

        ClaimRulePolicy uninitialized = new ClaimRulePolicy();

        [SetUp]
        public void Setup() {

        }

        [Test]
        public void MatchSeanNameClaim() {

            var claims = new List<Claim>();
            var me = new Claim("name", "Sean McArdle");
            claims.Add(me);

            Assert.IsTrue(matchSean.EvaluateRules(claims));
        }

        [Test]
        public void NegativeMatchSeanNameClaim() {
            var claims = new List<Claim>();
            var me = new Claim("name", "Sean McArdle");
            claims.Add(me);

            Assert.IsFalse(matchNotSean.EvaluateRules(claims));

            claims.Clear();
            var notme = new Claim("name", "Robin Williams");
            claims.Add(notme);

            Assert.IsTrue(matchNotSean.EvaluateRules(claims));
        }

        [Test]
        public void TypeCheckPatternMatchingOnClaim() {
            var msg = "Pattern matching should interpret this object as a Claim.";
            object me = new Claim("name", "Sean McArdle");
            
            var result = matchSean.EvaluateRules(me);
            Assert.IsTrue(result, msg);
        }

        [Test]
        public void TypeCheckPatternMatchingOnClaimCollection() {
            var msg = "Pattern matching should interpret Claims as such via DLR.";
            var claims = new List<object>();
            var me = new Claim("name", "Sean McArdle");
            claims.Add(me);

            // Let's add some junk that isn't a claim
            var alsoMe = new { name = "Dad" };
            claims.Add(alsoMe);

            var result = matchSean.EvaluateRules(claims);
            Assert.IsTrue(result, msg);


            // Let's add some junk that isn't a claim
            claims = new List<object>();
            alsoMe = new { name = "Dad" };
            claims.Add(alsoMe);
            result = true;
            result = matchSean.EvaluateRules(claims);
            Assert.IsFalse(result, msg);
        }

        [Test]
        public void GracefullyHandleNullClaims() {
            var msg = "Null objects should be handled gracefully. Since this runs inside an authorization rule, it should be true/false.";
            
            Claim nil = null;
            Assert.DoesNotThrow(() => matchSean.EvaluateRules(nil), msg);

            List<Claim> claimColl = null;
            Assert.DoesNotThrow(() => matchSean.EvaluateRules(claimColl), msg);
        }

        [Test]
        public void UninitializedPolicyShouldNotThrow() {
            var msg = "Uninitialized rules shouldn't throw.";
            var me = new Claim("name", "Sean McArdle");
            Assert.DoesNotThrow(() => uninitialized.EvaluateRules(me), msg);
            Assert.IsFalse(uninitialized.EvaluateRules(me), msg);
        }
    }
}