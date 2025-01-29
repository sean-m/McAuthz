using McAuthz.Interfaces;
using McAuthz.Policy;
using McAuthz.Requirements;
using McAuthz.Tests.Plumbing;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace McAuthz.Tests.PolicyTests {
    [TestFixture]
    public class FilterPolicyTests {
        ClaimsIdentity tharion = new ClaimsIdentity(new List<Claim> {
            new Claim("name", "Tharion Sunstrider"),
            new Claim("role", "admin"),
            new Claim("class", "mage"),
            new Claim("alignment", "lawful good")
        }, "TestAuthType", "displayName", "role");

        ClaimsIdentity xanderFirestormIdentity = new ClaimsIdentity(new List<Claim>
        {
            new Claim("name", "Xander Firestorm"),
            new Claim("title", "wields the power of fire and destruction"),
            new Claim("role", "member"),
            new Claim("primaryClass", "fire mage"),
            new Claim("secondaryClass", ""),
            new Claim("alignment", "chaotic evil"),
            new Claim("gold", "200"),
            new Claim("hp", "65"),
            new Claim("constitution", "10"),
            new Claim("strength", "8"),
            new Claim("intelligence", "20"),
            new Claim("agility", "12"),
            new Claim("speed", "10")
        }, "TestAuthType", "displayName", "role");

        IEnumerable<Adventurer> Adventurers { get; set; }
        IEnumerable<NPC> Monsters { get; set; }
        IEnumerable<NPC> NPCs { get; set; }

        RuleProvider RuleProvider { get; set; }

        [SetUp]
        public void Setup() {
            Adventurers = SMM.CsvFileReader.GetRecords<Adventurer>("./TestData/adventurers.csv").ToList();
            Monsters = SMM.CsvFileReader.GetRecords<NPC>("./TestData/monsters.csv").ToList();
            NPCs = SMM.CsvFileReader.GetRecords<NPC>("./TestData/npcs.csv").ToList();

            RuleProvider = new RuleProvider();
            var _rules = new List<RulePolicy>();
            var neutralMonstersOnly = new ResourceRulePolicy<NPC>() {
                Requirements = new Requirement[] {
                    new PropertyRequirement("Alignment","~*neutral*"),
                    new PropertyRequirement("Type", "~*monster*")
                }
            };
            _rules.Add(neutralMonstersOnly);

            var adventurerBardSilverleaf = new ResourceRulePolicy() {
                Requirements = new Requirement[] {
                    new PropertyRequirement(nameof(Adventurer.PrimaryClass),"~bard"),
                    new PropertyRequirement(nameof(Adventurer.Name), "~*silverleaf")
                },
                TargetType = "Adventurer"
            };
            _rules.Add(adventurerBardSilverleaf);


            var adminMageFilterPolicy = new FilterPolicy() {
                Name = "Full Mage List Available to Admin Mages",
                Requirements = new Requirement[]
                {
                    new RoleRequirement("admin"),
                    new ClaimRequirement("class", "mage"),
                    new PropertyRequirement("primaryClass", "*mage")
                },
                TargetType = typeof(Adventurer).Name,
            };
            _rules.Add(adminMageFilterPolicy);

            RuleProvider.PolicyCollection = _rules;
        }


        [Test]
        public void FilterPolicyShouldCreateAPredicateThatAssociatesAnIdentityAndTargetType() {
            // Tharion is an admin mage and should be able to see all of them
            var filter = RuleProvider.Filters<Adventurer>(tharion);
            Assert.That(filter, Is.Not.Null);

            var allMages = Adventurers.Where(x => x.PrimaryClass.Contains("mage"));

            var filtered = Adventurers.Where(filter);
            Assert.That(filtered, Is.Not.Null);
            Assert.That(filtered.Count(), Is.Not.EqualTo(Adventurers.Count()));
            Assert.That(filtered.Count(), Is.EqualTo(allMages.Count()));

            // Xander is not an admin mage and should not be able to see all of them
            var xanderFilter = RuleProvider.Filters<Adventurer>(xanderFirestormIdentity);
            Assert.That(filter, Is.Not.Null);
            var xanderScope = Adventurers.Where(xanderFilter);
            Assert.That(xanderScope.Count(), Is.Not.EqualTo(allMages.Count()));
        }

        [Test]
        public void AdminPolicyDoesNotApplyToNonAdmins()
        {
            // We've gotta make sure I did the thing right. If the policy doesn't get associated
            // to the correct identity, that's a problem.
            
            var tharionFilter = RuleProvider.Filters<Adventurer>(tharion);
            var xanderFilter = RuleProvider.Filters<Adventurer>(xanderFirestormIdentity);
            
            Assert.That(tharionFilter, Is.Not.Null);
            Assert.That(xanderFilter, Is.Not.Null);
            Assert.That(tharionFilter, Is.Not.EqualTo(xanderFilter));
            CollectionAssert.AreEquivalent(Adventurers.Where(tharionFilter), Adventurers.Where(tharionFilter));
            CollectionAssert.AreNotEquivalent(Adventurers.Where(tharionFilter), Adventurers.Where(xanderFilter));
        }
    }
}
