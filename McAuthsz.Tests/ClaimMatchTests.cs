using McAuthz.Policy;
using McAuthz.Requirements;
using System.Security.Claims;

namespace McAuthz.Tests {
    public class ClaimMatchTests {

        RequestPolicy matchSean = new RequestPolicy(
            new[] { new ClaimRequirement("name", "Sean McArdle") }) {
            Route = "/api/User"
        };

        RequestPolicy matchNotSean = new RequestPolicy(
           new[] { new ClaimRequirement("name", "!Sean McArdle") }) {
            Route = "/api/User"
        };

        RequestPolicy uninitialized = new RequestPolicy();

        [SetUp]
        public void Setup() {

        }

        [Test]
        public void MatchSeanNameClaim() {

            var claims = new List<Claim>();
            var me = new Claim("name", "Sean McArdle");
            claims.Add(me);
            bool result = matchSean.EvaluatePrincipal(claims);
            Assert.IsTrue(result);
        }

        [Test]
        public void NegativeMatchSeanNameClaim() {
            var claims = new List<Claim>();
            var me = new Claim("name", "Sean McArdle");
            claims.Add(me);

            Assert.IsFalse(matchNotSean.EvaluatePrincipal(claims));

            claims.Clear();
            var notme = new Claim("name", "Robin Williams");
            claims.Add(notme);

            Assert.IsTrue(matchNotSean.EvaluatePrincipal(claims));
        }

        [Test]
        public void TypeCheckPatternMatchingOnClaim() {
            var msg = "Pattern matching should interpret this object as a Claim.";
            object me = new Claim("name", "Sean McArdle");

            var result = matchSean.EvaluatePrincipal( me );
            Assert.IsTrue(result, msg);
        }

        [Test]
        public void GracefullyHandleNullClaims() {
            var msg = "Null objects should be handled gracefully. Since this runs inside an authorization rule, it should be true/false.";

            Claim nil = null;
            Assert.DoesNotThrow(() => matchSean.EvaluatePrincipal(nil), msg);

            List<Claim> claimColl = null;
            Assert.DoesNotThrow(() => matchSean.EvaluatePrincipal(claimColl), msg);
        }

        [Test]
        public void UninitializedPolicyShouldNotThrow() {
            var msg = "Uninitialized rules shouldn't throw.";
            var me = new Claim("name", "Sean McArdle");
            Assert.DoesNotThrow(() => uninitialized.EvaluatePrincipal(me), msg);
            Assert.IsFalse(uninitialized.EvaluatePrincipal(me), msg);
        }
    }
}