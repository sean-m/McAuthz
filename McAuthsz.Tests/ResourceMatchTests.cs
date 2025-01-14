using McAuthz.Interfaces;
using McAuthz.Policy;
using McAuthz.Tests.Plumbing;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NUnit;
using McAuthz.Requirements;

namespace McAuthz.Tests {
    /* This tests the capabilities of using rules for resource based authorization.
     * In asp.net core this means rules are evaluated against objects returned
     * to the client from the server. Authorization in the response side of
     * the middleware pipeline. Resource in this context just means the
     * .net object being sent back, the 'Resource' property of the HTTP context.
     * https://learn.microsoft.com/en-us/aspnet/core/security/authorization/resourcebased?view=aspnetcore-7.0
    // * */
    public class ResourceMatchTests {

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


            RuleProvider.PolicyCollection = _rules;
        }


        [Test]
        public void TestCsvDataLoader() {
            Assert.NotNull(Adventurers);
            Assert.IsTrue(Adventurers.Count() >= 10);

            Assert.NotNull(Monsters);
            Assert.IsTrue(Adventurers.Count() >= 5);

            Assert.NotNull(NPCs);
        }

        [Test]
        public void TestFilteringObjectsBasedOnStringContents() {
            var policies = RuleProvider.Policies(typeof(NPC));
            Assert.NotNull(policies, $"Something wrong with he rule provider. No poliices for type: {typeof(NPC).Name}");

            var filtered = Monsters.Where(m => policies.Any(p => p.EvaluateModel<NPC>(m).Succes));
            Assert.IsFalse(filtered.Count() == Monsters.Count(), "The filtered data set has the same number of records as the source set, something's funky.");
            Assert.IsTrue(filtered.Count() > 0, "Policies were applied but none succeeded for the collection of monsters.");
        }
    }

    public enum CharClass {
        warior = 1,
        cleric = 2,
        mage = 4,
        rogue = 8,
        theif = 16,
        bard = 32,
        fighter = 64,
        ranger = 128,
        warlock = 256,
        monk = 512,
    }
    public class Adventurer {
        // Properties
        public string Name { get; init; }
        public string Title { get; init; }
        public string Renown { get; init; }
        public CharClass PrimaryClass { get; init; }
        public CharClass SecondaryClass { get; init; }
        public string Alignment { get; init; }
        public int Gold { get; set; } = 0;
        public int Hp { get; set; } = 40;
        public int Constitution { get; set; } = 4;
        public int Strength { get; set; } = 4;
        public int Intelligence { get; set; } = 4;
        public int Agility { get; set; } = 4;
        public int Speed { get; set; } = 4;

        public Adventurer() { }
        public Adventurer(string name, string title, string renown, CharClass primaryClass,
            CharClass secondaryClass, string alignment,
            int gold = 0, int hp = 40, int constitution = 4, int strength = 4,
            int intelligence = 4, int agility = 4, int speed = 4) {
            Name = name;
            Title = title;
            Renown = renown;
            PrimaryClass = primaryClass;
            SecondaryClass = secondaryClass;
            Alignment = alignment;
            Gold = gold;
            Hp = hp;
            Constitution = constitution;
            Strength = strength;
            Intelligence = intelligence;
            Agility = agility;
            Speed = speed;
        }
    }
    public class NPC {
        public string Type { get; set; }
        public string Name { get; init; }
        public string Title { get; init; }
        public string Renown { get; init; }
        public string Alignment { get; init; }
        public int Hp { get; set; }
        public int Strength { get; set; }

        public NPC() { }
        public NPC(string name, string title, string alignment, int hp, int strength) {
            Name = name;
            Title = title;
            Alignment = alignment;
            Hp = hp;
            Strength = strength;
        }
    }


}
