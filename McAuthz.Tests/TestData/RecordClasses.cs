using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace McAuthz.Tests.TestData {

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
        public string PrimaryClass { get; init; }
        public string SecondaryClass { get; init; }
        public string Alignment { get; init; }
        public int Gold { get; set; } = 0;
        public int Hp { get; set; } = 40;
        public int Constitution { get; set; } = 4;
        public int Strength { get; set; } = 4;
        public int Intelligence { get; set; } = 4;
        public int Agility { get; set; } = 4;
        public int Speed { get; set; } = 4;

        public Adventurer() { }
        public Adventurer(string name, string title, string renown, string primaryClass,
            string secondaryClass, string alignment,
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
