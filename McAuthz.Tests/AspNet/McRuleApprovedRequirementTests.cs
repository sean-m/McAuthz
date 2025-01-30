using McAuthz.Interfaces;
using McAuthz.Policy;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using System.Collections.Generic;
using System.Reflection;
using System.Security.Claims;
using McAuthz.Requirements;
using System.Net.Http;
using McAuthz.Tests.Plumbing;

namespace McAuthz.Tests.AspNet
{
    [TestFixture]
    public class McRuleApprovedRequirementTests {
        private TestLogger _testLogger;

        [SetUp]
        public void SetUp()
        {
            _testLogger = new TestLogger();
        }

        [Test]
        public void IsAuthorized_ShouldReturnTrue_WhenUserIsAuthenticatedAndMeetsPolicy()
        {
            // Arrange
            var testRuleProvider = new RuleProvider();
            var requirement = new McRuleApprovedRequirement(_testLogger, testRuleProvider);

            var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name, "John Doe"),
                        new Claim("role", "Admin")
                    };
            var identity = new ClaimsIdentity(claims, "TestAuthType");
            var principal = new ClaimsPrincipal(identity);

            var httpContext = new DefaultHttpContext();
            var mockRequest = new MockHttpRequest(httpContext)
            {
                Method = "GET",
                Path = "/TestController"
            };

            // Use reflection to set the private _request field
            var requestField = typeof(DefaultHttpContext).GetField("_request", BindingFlags.NonPublic | BindingFlags.Instance);
            requestField?.SetValue(httpContext, mockRequest);

            var context = new AuthorizationHandlerContext(new[] { requirement }, principal, httpContext);

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
            var result = requirement.IsAuthorized(context);

            // Assert
            Assert.That(result.Item1, Is.True);
        }

        [Test]
        public void IsAuthorized_ShouldReturnFalse_WhenUserIsAuthenticatedAndDoesNotMeetPolicy()
        {
            // Arrange
            var testRuleProvider = new RuleProvider();
            var requirement = new McRuleApprovedRequirement(_testLogger, testRuleProvider);

            var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name, "John Doe"),
                        new Claim("role", "User")
                    };
            var identity = new ClaimsIdentity(claims, "TestAuthType");
            var principal = new ClaimsPrincipal(identity);

            var httpContext = new DefaultHttpContext();
            var mockRequest = new MockHttpRequest(httpContext)
            {
                Method = "GET",
                Path = "/TestController"
            };

            // Use reflection to set the private _request field
            var requestField = typeof(DefaultHttpContext).GetField("_request", BindingFlags.NonPublic | BindingFlags.Instance);
            requestField?.SetValue(httpContext, mockRequest);

            var context = new AuthorizationHandlerContext(new[] { requirement }, principal, httpContext);

            var policies = new List<RulePolicy>
                    {
                        new RequestPolicy
                        {
                            Name = "Admin Policy",
                            Route = "TestController",
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
            var result = requirement.IsAuthorized(context);

            // Assert
            Assert.That(result.Item1, Is.False);
        }

        [Test]
        public void IsAuthorized_ShouldReturnTrue_WhenUserIsUnauthenticatedAndMeetsPolicy()
        {
            // Arrange
            var testRuleProvider = new RuleProvider();
            var requirement = new McRuleApprovedRequirement(_testLogger, testRuleProvider);

            var identity = new ClaimsIdentity();
            var principal = new ClaimsPrincipal(identity);

            var httpContext = new DefaultHttpContext();
            var mockRequest = new MockHttpRequest(httpContext)
            {
                Method = "GET",
                Path = "/TestController"
            };

            // Use reflection to set the private _request field
            var requestField = typeof(DefaultHttpContext).GetField("_request", BindingFlags.NonPublic | BindingFlags.Instance);
            requestField?.SetValue(httpContext, mockRequest);

            var context = new AuthorizationHandlerContext(new[] { requirement }, principal, httpContext);

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
            var result = requirement.IsAuthorized(context);

            // Assert
            Assert.That(result.Item1, Is.True);
        }

        [Test]
        public void IsAuthorized_ShouldReturnFalse_WhenUserIsUnauthenticatedAndDoesNotMeetPolicy()
        {
            // Arrange
            var testRuleProvider = new RuleProvider();
            var requirement = new McRuleApprovedRequirement(_testLogger, testRuleProvider);

            var identity = new ClaimsIdentity();
            var principal = new ClaimsPrincipal(identity);

            var httpContext = new DefaultHttpContext();
            var mockRequest = new MockHttpRequest(httpContext)
            {
                Method = "GET",
                Path = "/TestController"
            };

            // Use reflection to set the private _request field
            var requestField = typeof(DefaultHttpContext).GetField("_request", BindingFlags.NonPublic | BindingFlags.Instance);
            requestField?.SetValue(httpContext, mockRequest);

            var context = new AuthorizationHandlerContext(new[] { requirement }, principal, httpContext);

            var policies = new List<RulePolicy>
                    {
                        new RequestPolicy
                        {
                            Name = "Unauthenticated Admin Policy",
                            Route = "TestController",
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
            var result = requirement.IsAuthorized(context);

            // Assert
            Assert.That(result.Item1, Is.False);
        }

        [Test]
        public void IsAuthorized_ShouldReturnFalse_WhenHttpMethodDoesNotMatchPolicy()
        {
            // Arrange
            var testRuleProvider = new RuleProvider();
            var requirement = new McRuleApprovedRequirement(_testLogger, testRuleProvider);

            var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name, "John Doe"),
                        new Claim("role", "Admin")
                    };
            var identity = new ClaimsIdentity(claims, "TestAuthType");
            var principal = new ClaimsPrincipal(identity);

            var httpContext = new DefaultHttpContext();
            var mockRequest = new MockHttpRequest(httpContext)
            {
                Method = "POST",
                Path = "/TestController"
            };

            // Use reflection to set the private _request field
            var requestField = typeof(DefaultHttpContext).GetField("_request", BindingFlags.NonPublic | BindingFlags.Instance);
            requestField?.SetValue(httpContext, mockRequest);

            var context = new AuthorizationHandlerContext(new[] { requirement }, principal, httpContext);

            var policies = new List<RulePolicy>
                    {
                        new RequestPolicy
                        {
                            Name = "Admin Policy",
                            Route = "TestController",
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
            var result = requirement.IsAuthorized(context);

            // Assert
            Assert.That(result.Item1, Is.False);
        }

        [Test]
        public void IsAuthorized_ShouldReturnFalse_WhenHttpMethodDoesNotMatchPolicy_Unauthenticated()
        {
            // Arrange
            var testRuleProvider = new RuleProvider();
            var requirement = new McRuleApprovedRequirement(_testLogger, testRuleProvider);

            var identity = new ClaimsIdentity();
            var principal = new ClaimsPrincipal(identity);

            var httpContext = new DefaultHttpContext();
            var mockRequest = new MockHttpRequest(httpContext)
            {
                Method = "POST",
                Path = "/TestController"
            };

            // Use reflection to set the private _request field
            var requestField = typeof(DefaultHttpContext).GetField("_request", BindingFlags.NonPublic | BindingFlags.Instance);
            requestField?.SetValue(httpContext, mockRequest);

            var context = new AuthorizationHandlerContext(new[] { requirement }, principal, httpContext);

            var policies = new List<RulePolicy>
                    {
                        new RequestPolicy
                        {
                            Name = "Unauthenticated Policy",
                            Route = "TestController",
                            Action = "GET",
                            Authentication = AuthenticationStatus.Unauthenticated,
                            Requirements = new List<Requirement>()
                        }
                    };

            testRuleProvider.SetPolicies(policies);

            // Act
            var result = requirement.IsAuthorized(context);

            // Assert
            Assert.That(result.Item1, Is.False);
        }

        [Test]
        public void IsAuthorized_WithModel_ShouldReturnTrue_WhenModelMeetsPolicy()
        {
            // Arrange
            var testRuleProvider = new RuleProvider();
            var requirement = new McRuleApprovedRequirement(_testLogger, testRuleProvider);

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, "John Doe"),
                new Claim("role", "Admin")
            };
            var identity = new ClaimsIdentity(claims, "TestAuthType");
            var principal = new ClaimsPrincipal(identity);

            var httpContext = new DefaultHttpContext();
            var mockRequest = new MockHttpRequest(httpContext)
            {
                Method = "GET",
                Path = "/TestController"
            };

            // Use reflection to set the private _request field
            var requestField = typeof(DefaultHttpContext).GetField("_request", BindingFlags.NonPublic | BindingFlags.Instance);
            requestField?.SetValue(httpContext, mockRequest);

            var context = new AuthorizationHandlerContext(new[] { requirement }, principal, httpContext);

            var policies = new List<RulePolicy>
            {
                new RequestPolicy
                {
                    Name = "Model Policy",
                    Route = "/TestController",
                    Action = "GET",
                    Authentication = AuthenticationStatus.Authenticated,
                    Requirements = new List<Requirement>
                    {
                        new PropertyRequirement("Name", "TestModel")
                    }
                }
            };

            testRuleProvider.SetPolicies(policies);

            var model = new { Name = "TestModel" };

            // Act
            var result = requirement.IsAuthorized(context, model);

            // Assert
            Assert.That(result.Item1, Is.True);
        }

        [Test]
        public void IsAuthorized_WithModel_ShouldReturnFalse_WhenModelDoesNotMeetPolicy()
        {
            // Arrange
            var testRuleProvider = new RuleProvider();
            var requirement = new McRuleApprovedRequirement(_testLogger, testRuleProvider);

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, "John Doe"),
                new Claim("role", "Admin")
            };
            var identity = new ClaimsIdentity(claims, "TestAuthType");
            var principal = new ClaimsPrincipal(identity);

            var httpContext = new DefaultHttpContext();
            var mockRequest = new MockHttpRequest(httpContext)
            {
                Method = "GET",
                Path = "/TestController"
            };

            // Use reflection to set the private _request field
            var requestField = typeof(DefaultHttpContext).GetField("_request", BindingFlags.NonPublic | BindingFlags.Instance);
            requestField?.SetValue(httpContext, mockRequest);

            var context = new AuthorizationHandlerContext(new[] { requirement }, principal, httpContext);

            var policies = new List<RulePolicy>
            {
                new RequestPolicy
                {
                    Name = "Model Policy",
                    Route = "/TestController",
                    Action = "GET",
                    Authentication = AuthenticationStatus.Authenticated,
                    Requirements = new List<Requirement>
                    {
                        new PropertyRequirement("Name", "TestModel")
                    }
                }
            };

            testRuleProvider.SetPolicies(policies);

            var model = new { Name = "NonMatchingModel" };

            // Act
            var result = requirement.IsAuthorized(context, model);

            // Assert
            Assert.That(result.Item1, Is.False);
        }

        private class TestLogger : ILogger {
            public IDisposable BeginScope<TState>(TState state) => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception, Func<TState, Exception, string> formatter)
            {
                // No-op
            }
        }
    }
}
