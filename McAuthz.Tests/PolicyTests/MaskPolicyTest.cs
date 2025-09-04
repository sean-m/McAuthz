using McAuthz.Policy;
using System.Dynamic;
using System.Reflection;

namespace McAuthz.Tests.PolicyTests;

[TestFixture]
public class MaskPolicyTest {

    IEnumerable<Adventurer> Adventurers { get; set; }

    [SetUp]
    public void Setup()
    {
        Adventurers = SMM.CsvFileReader.GetRecords<Adventurer>("./TestData/adventurers.csv").ToList();
    }

    [Test]
    public void MaskPolicy_ShouldIncludeOnlySpecifiedProperties()
    {
        // Arrange
        var adventurer = new Adventurer
        {
            Name = "Aragorn",
            Title = "King",
            Renown = "Legendary",
            PrimaryClass = "ranger",
            SecondaryClass = "fighter",
            Alignment = "Lawful Good",
            Gold = 777,
            Hp = 80,
            Constitution = 10,
            Strength = 15,
            Intelligence = 12,
            Agility = 14,
            Speed = 10
        };

        var maskProperties = new[] { "Name", "Title", "Gold" };
        var maskPolicy = new MaskPolicy<Adventurer>(maskProperties);

        // Act
        var masked = maskPolicy.ApplyMask(adventurer);

        Assert.That(adventurer.Name, Is.EqualTo(masked.Name));
        Assert.That(adventurer.Title, Is.EqualTo(masked.Title));
        Assert.That(adventurer.Gold, Is.EqualTo(masked.Gold));
        Assert.IsNull(masked.Renown);
    }

    [Test]
    public void MaskPolicy_ShouldIgnoreNonexistentProperties()
    {
        // Arrange
        var adventurer = Adventurers.First();
        var maskPolicy = new MaskPolicy<Adventurer>(new[] { "Name", "NonexistentProperty" });

        dynamic masked = new ExpandoObject();
        masked = maskPolicy.ApplyMask(adventurer);

        // Assert
        var dict = ToDictionary(masked);
        Assert.IsNotNull(dict, "Masked result should be a dictionary");
        Assert.IsTrue(dict.ContainsKey("Name"));
        Assert.IsFalse(dict.ContainsKey("NonexistentProperty"));
    }

    internal Dictionary<string, object> ToDictionary<T>(T source)
    {
        if (source == null)
            throw new ArgumentNullException(nameof(source));

        var dict = new Dictionary<string, object>();
        foreach (PropertyInfo prop in typeof(T).GetProperties(BindingFlags.Public | BindingFlags.Instance))
        {
            dict[prop.Name] = prop.GetValue(source, null);
        }
        return dict;
    }
}
