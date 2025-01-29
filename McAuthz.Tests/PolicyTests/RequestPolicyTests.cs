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
    public class RequestPolicyTests {
        ClaimsIdentity tharion = new ClaimsIdentity(new List<Claim> {
            new Claim("name", "Tharion Sunstrider"),
            new Claim("role", "admin"),
            new Claim("primaryClass", "mage"),
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


        ClaimsIdentity miraLightbringerIdentity = new ClaimsIdentity(new List<Claim>
        {
            new Claim("role", "admin"),
            new Claim("name", "Mira Lightbringer"),
            new Claim("title", "healer and protector of the weak"),
            new Claim("primaryClass", "paladin"),
            new Claim("secondaryClass", ""),
            new Claim("alignment", "lawful good"),
            new Claim("gold", "120"),
            new Claim("hp", "70"),
            new Claim("constitution", "12"),
            new Claim("strength", "10"),
            new Claim("intelligence", "18"),
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
                Name = "Neutral Monsters Only",
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


            var adminMagesCanPerformAllActionsToTheAdminRoute = new RequestPolicy() {
                Name = "Allow all /admin path access to admin mages",
                Requirements = new Requirement[] {
                    new RoleRequirement("admin"),
                    new ClaimRequirement("primaryClass", "~*mage*")
                },
                Action = "*",
                Route = "/admin/*",
            };
            adminMagesAllAdminActions = adminMagesCanPerformAllActionsToTheAdminRoute;

            var allMagesCanPerformGetActionsToAdminRoute = new RequestPolicy() {
                Name = "Allow GET /admin access to admin mages",
                Requirements = new Requirement[] {
                    new ClaimRequirement("primaryClass", "~*mage*")
                },
                Action = "GET",
                Route = "/admin/*",
            };
            getFromAdminForMages = allMagesCanPerformGetActionsToAdminRoute;

            RuleProvider.PolicyCollection = _rules;
        }


        private RequestPolicy? adminMagesAllAdminActions;
        private RequestPolicy? getFromAdminForMages;

        [Test]
        public void AdminPolicyDoesNotApplyToNonAdmins() {
            // Only Tharion the admin make should be able to POST to the admin page, though
            // determining whether this policy applies to a given request is up to the role provider
            // right now. Though that may change since FilterPolicies also determine their own scope.
            Assert.That(adminMagesAllAdminActions?.EvaluatePrincipal(tharion).Succes, Is.True);
            Assert.That(adminMagesAllAdminActions?.EvaluatePrincipal(xanderFirestormIdentity).Succes, Is.False);

            // Mira has the admin role but is not a mage so can't post to the admin page
            Assert.That(adminMagesAllAdminActions?.EvaluatePrincipal(miraLightbringerIdentity).Succes, Is.False);
            Assert.That(getFromAdminForMages?.EvaluatePrincipal(miraLightbringerIdentity).Succes, Is.False);
        }

        [Test]
        public void PolicyWithoutARoleRequirementAppliesToThoseWithARole() {

            // Both mages should be able to get from the admin page but Mira can't
            Assert.That(getFromAdminForMages?.EvaluatePrincipal(tharion).Succes, Is.True);
            Assert.That(getFromAdminForMages?.EvaluatePrincipal(xanderFirestormIdentity).Succes, Is.True);
            Assert.That(getFromAdminForMages?.EvaluatePrincipal(miraLightbringerIdentity).Succes, Is.False);
        }
    }
}
