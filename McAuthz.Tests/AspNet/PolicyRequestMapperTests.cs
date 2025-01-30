using McAuthz.Interfaces;
using McAuthz.Policy;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using System.Collections.Generic;
using System.Security.Claims;
using McAuthz.Requirements;
using McAuthz.Tests.Plumbing;

namespace McAuthz.Tests.AspNet
{
    [TestFixture]
    public class PolicyRequestMapperTests {
        private TestLogger _testLogger;
        IEnumerable<NPC> NPCs { get; set; }

        [SetUp]
        public void SetUp()
        {
            _testLogger = new TestLogger();
            NPCs = SMM.CsvFileReader.GetRecords<NPC>("./TestData/npcs.csv").ToList();
        }

        [Test]
        public void IsAuthorized_ShouldReturnTrue_WhenUserIsAuthenticatedAndMeetsPolicy()
        {
            // Arrange
            var testRuleProvider = new RuleProvider();
            var policyRequestMapper = new PolicyRequestMapper(_testLogger, testRuleProvider);

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, "John Doe"),
                new Claim("role", "Admin")
            };
            var identity = new ClaimsIdentity(claims, "TestAuthType");
            var principal = new ClaimsPrincipal(identity);

            var httpContext = new DefaultHttpContext
            {
                User = principal
            };
            httpContext.Request.Method = "GET";
            httpContext.Request.Path = "/TestController";

            var policies = new List<RulePolicy>
            {
                new RequestPolicy
                {
                    Name = "Admin Policy",
                    Route = "/TestController",
                    Action = "GET",
                    Authentication = AuthenticationStatus.Authenticated,
                    Requirements = new List<Requirement>
                    {
                        new ClaimRequirement("role", "Admin")
                    }
                }
            };

            testRuleProvider.SetPolicies(policies);

            // Act
            var result = policyRequestMapper.IsAuthorized(httpContext);

            // Assert
            Assert.IsTrue(result);
        }

        [Test]
        public void IsAuthorized_ShouldReturnFalse_WhenUserIsAuthenticatedAndDoesNotMeetPolicy()
        {
            // Arrange
            var testRuleProvider = new RuleProvider();
            var policyRequestMapper = new PolicyRequestMapper(_testLogger, testRuleProvider);

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, "John Doe"),
                new Claim("role", "User")
            };
            var identity = new ClaimsIdentity(claims, "TestAuthType");
            var principal = new ClaimsPrincipal(identity);

            var httpContext = new DefaultHttpContext
            {
                User = principal
            };
            httpContext.Request.Method = "GET";
            httpContext.Request.Path = "/TestController";

            var policies = new List<RulePolicy>
            {
                new RequestPolicy
                {
                    Name = "Admin Policy",
                    Route = "/TestController",
                    Action = "GET",
                    Authentication = AuthenticationStatus.Authenticated,
                    Requirements = new List<Requirement>
                    {
                        new ClaimRequirement("role", "Admin")
                    }
                }
            };

            testRuleProvider.SetPolicies(policies);

            // Act
            var result = policyRequestMapper.IsAuthorized(httpContext);

            // Assert
            Assert.IsFalse(result);
        }

        [Test]
        public void IsAuthorized_ShouldReturnTrue_WhenUserIsUnauthenticatedAndMeetsPolicy()
        {
            // Arrange
            var testRuleProvider = new RuleProvider();
            var policyRequestMapper = new PolicyRequestMapper(_testLogger, testRuleProvider);

            var identity = new ClaimsIdentity();
            var principal = new ClaimsPrincipal(identity);

            var httpContext = new DefaultHttpContext
            {
                User = principal
            };
            httpContext.Request.Method = "GET";
            httpContext.Request.Path = "/TestController";

            var policies = new List<RulePolicy>
            {
                new RequestPolicy
                {
                    Name = "Unauthenticated Policy",
                    Route = "/TestController",
                    Action = "GET",
                    Authentication = AuthenticationStatus.Unauthenticated,
                    Requirements = new List<Requirement>()
                }
            };

            testRuleProvider.SetPolicies(policies);

            // Act
            var result = policyRequestMapper.IsAuthorized(httpContext);

            // Assert
            Assert.IsTrue(result);
        }

        [Test]
        public void IsAuthorized_ShouldReturnFalse_WhenUserIsUnauthenticatedAndDoesNotMeetPolicy()
        {
            // Arrange
            var testRuleProvider = new RuleProvider();
            var policyRequestMapper = new PolicyRequestMapper(_testLogger, testRuleProvider);

            var identity = new ClaimsIdentity();
            var principal = new ClaimsPrincipal(identity);

            var httpContext = new DefaultHttpContext
            {
                User = principal
            };
            httpContext.Request.Method = "GET";
            httpContext.Request.Path = "/TestController";

            var policies = new List<RulePolicy>
            {
                new RequestPolicy
                {
                    Name = "Unauthenticated Admin Policy",
                    Route = "/TestController",
                    Action = "GET",
                    Authentication = AuthenticationStatus.Unauthenticated,
                    Requirements = new List<Requirement>
                    {
                        new ClaimRequirement("role", "Admin")
                    }
                }
            };

            testRuleProvider.SetPolicies(policies);

            // Act
            var result = policyRequestMapper.IsAuthorized(httpContext);

            // Assert
            Assert.IsFalse(result);
        }

        [Test]
        public void IsAuthorized_ShouldReturnFalse_WhenResourceDoesNotMeetPolicy()
        {
            // Arrange
            var testRuleProvider = new RuleProvider();
            var policyRequestMapper = new PolicyRequestMapper(_testLogger, testRuleProvider);

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, "John Doe"),
                new Claim("role", "User")
            };
            var identity = new ClaimsIdentity(claims, "TestAuthType");
            var principal = new ClaimsPrincipal(identity);

            var httpContext = new DefaultHttpContext
            {
                User = principal,
                Request =
                {
                    Method = "GET",
                    Path = "/TestController"
                },
                Items =
                {
                    ["Resource"] = new NPC { Name = "TestNPC" }
                }
            };

            var policies = new List<RulePolicy>
            {
                new ResourceRulePolicy
                {
                    Name = "Resource Policy",
                    Route = "/TestController",
                    Action = "GET",
                    Authentication = AuthenticationStatus.Authenticated,
                    Requirements = new List<Requirement>
                    {
                        new PropertyRequirement("Name", "NonMatchingNPC")
                    }
                }
            };

            testRuleProvider.SetPolicies(policies);

            // Act
            var result = policyRequestMapper.IsAuthorized(httpContext);

            // Assert
            Assert.IsFalse(result);
        }

        private class TestLogger : ILogger<PolicyRequestMapper> {
            public IDisposable BeginScope<TState>(TState state) => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception, Func<TState, Exception, string> formatter)
            {
                // No-op
            }
        }
    }
}

