﻿using McAuthz.Interfaces;
using McAuthz.Policy;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NUnit;
using McAuthz.Requirements;
using McAuthz.Tests.TestData;
using RuleProvider = McAuthz.Tests.Plumbing.RuleProvider;

namespace McAuthz.Tests.PredicateTests {
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

            var adventurerBardSilverleaf = new ResourceRulePolicy() {
                Requirements = new Requirement[] {
                    new PropertyRequirement(nameof(Adventurer.PrimaryClass),"~bard"),
                    new PropertyRequirement(nameof(Adventurer.Name), "~*silverleaf")
                },
                TargetType = "Adventurer"
            };
            _rules.Add(adventurerBardSilverleaf);

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
        public void TestFilteringTypedObjectsBasedOnStringContents() {
            var policies = RuleProvider.Policies(typeof(NPC));
            Assert.NotNull(policies, $"Something wrong with he rule provider. No poliices for type: {typeof(NPC).Name}");

            var filtered = Monsters.Where(m => policies.Any(p => p.EvaluateModel<NPC>(m).Succes));
            Assert.IsFalse(filtered.Count() == Monsters.Count(), "The filtered data set has the same number of records as the source set, something's funky.");
            Assert.IsTrue(filtered.Count() > 0, "Policies were applied but none succeeded for the collection of monsters.");
        }

        [Test]
        public void TestFilteringObjectsBasedOnStringContents() {
            var policies = RuleProvider.Policies(typeof(Adventurer));
            Assert.NotNull(policies, $"Something wrong with he rule provider. No poliices for type: {typeof(Adventurer).Name}");

            var filtered = Adventurers.Where(m => policies.Any(p => p.EvaluateModel(m).Succes));
            Assert.IsFalse(filtered.Count() == Adventurers.Count(), "The filtered data set has the same number of records as the source set, something's funky.");
            Assert.IsTrue(filtered.Count() >= 2, $"There should be two Silverleaf siblings who are bards but we matched on {filtered.Count()}.");
        }
    }



}
