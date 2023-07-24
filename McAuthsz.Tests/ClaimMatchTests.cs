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
    }
}