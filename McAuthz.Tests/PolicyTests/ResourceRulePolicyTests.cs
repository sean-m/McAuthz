using McAuthz.Policy;
using McAuthz.Requirements;
using NUnit.Framework;
using System.Collections.Generic;
using System.Security.Claims;
using McAuthz.Interfaces;
using McAuthz.Tests.Plumbing;
using McAuthz.Tests.TestData;

namespace McAuthz.Tests.PolicyTests
{
    [TestFixture]
    public class ResourceRulePolicyTests
    {
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


            var adminMageFilterPolicy = new FilterPolicy()
            {
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
        public void ResourceRulePolicy_ShouldMatchRequirements()
        {
            // Arrange
            var requirements = new Requirement[]
            {
                new PropertyRequirement("name", "John Doe"),
                new PropertyRequirement("topic", "Office News")
            };
            var policy = new ResourceRulePolicy
            {
                Requirements = requirements,
                Name = "Test Policy",
                TargetType = "TestType"
            };

            var inputs = new Dictionary<string, string>
            {
                { "name", "John Doe" },
                { "topic", "Office News" }
            };

            // Act
            var result = policy.EvaluateModel(inputs);

            // Assert
            Assert.IsTrue(result.Succes);
        }

        [Test]
        public void ResourceRulePolicy_ShouldNotMatchRequirements()
        {
            // Arrange
            var requirements = new Requirement[]
            {
                new PropertyRequirement("name", "John Doe"),
                new PropertyRequirement("topic", "Office News")
            };
            var policy = new ResourceRulePolicy
            {
                Requirements = requirements,
                Name = "Test Policy",
                TargetType = "TestType"
            };

            var inputs = new Dictionary<string, string>
            {
                { "name", "Jane Doe" },
                { "topic", "Office News" }
            };

            // Act
            var result = policy.EvaluateModel(inputs);

            // Assert
            Assert.IsFalse(result.Succes);
        }

        [Test]
        public void ResourceRulePolicyWithGenericType()
        {
            // Arrange
            var requirements = new Requirement[]
            {
                new PropertyRequirement("Alignment","~*neutral*"),
                new PropertyRequirement("Type", "~*monster*")
            };
            var policy = new ResourceRulePolicy<NPC>()
            {
                Requirements = requirements,
                Name = "Neutral Monster Policy",
            };

            Assert.That(policy.TargetType, Is.EqualTo(typeof(NPC).Name));
            
            
            // Act
            var results = Monsters.Select(m => new {result = policy.EvaluateModel(m), monster = m});
            
            // Assert
            Assert.IsTrue(results.Any(r => r.result.Succes));
            Assert.IsTrue(results.Where(r => 
                r.monster.Alignment.ToLower().Contains("neutral") 
                && r.monster.Type.ToLower().Contains("monster")
                ).All(r => r.result.Succes)
            );
        }
    }
}
