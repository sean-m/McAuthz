using McAuthz.Requirements;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace McAuthz.Tests.PredicateTests {
    [TestFixture]
    public class PropertyMatchTests {
        Dictionary<string,string> npc = new Dictionary<string, string>() {
            {"type", "monster"},
            {"alignment", "Neutral"},
            {"name", "wisp" }
        };

        NPC npc2 = new NPC {
            Type = "monster",
            Alignment = "Neutral",
            Name = "wisp"
        };

        [Test]
        public void PropertyRequirementWorksOnDictionary() {
            var requirement = new PropertyRequirement("alignment", "~*neutral*");
            var func = requirement.GetDictionaryFunc();
            //string expressionString = requirement.GetDictionaryFuncString();
            Assert.That(func(npc), Is.True);
        }

        [Test]
        public void PropertyRequirementCaseInsensitiveValues() {
            var requirement = new PropertyRequirement("alignment", "~*neutral*");
            var func = requirement.GetDictionaryFunc();
            Assert.That(func(npc), Is.True);

            var requirementCaseSensitive = new PropertyRequirement("alignment", "*neutral*");
            var funcCaseSensitive = requirementCaseSensitive.GetDictionaryFunc();
            Assert.That(funcCaseSensitive(npc), Is.False);
        }

        [Test]
        public void PropertyRequirementWorksOnObject() {
            var requirement = new PropertyRequirement("Alignment", "~*neutral*");
            var func = requirement.GetPropertyFunc<NPC>();
            Assert.That(func(npc2), Is.True);
        }
    }
}
