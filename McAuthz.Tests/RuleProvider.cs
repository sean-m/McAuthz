using McAuthz.Interfaces;
using McAuthz.Policy;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework.Constraints;

namespace McAuthz.Tests.Plumbing {

    // The intent of the RuleProviderInterface is that an application
    // can create it's own collection of rules that can be loaded
    // just-in-time when evaluating them. Or not, the provider could
    // hand back the same set of rules every time, like this one does.
    // I wrote it for testing the authorization middleware, probably
    // shouldn't use it in your own stuff.
    // Sean McArdle  - 07/2023
    public class RuleProvider : RuleProviderInterface {

        public IEnumerable<RulePolicy> PolicyCollection { get; internal set; } = new List<RulePolicy> ();

        public IEnumerable<RulePolicy> Policies(Type type) {
            System.Diagnostics.Trace.WriteLine($"{DateTime.Now} RuleProvider.Rules(type) : Rule set fetched.");
            return PolicyCollection.Where(x => x.TargetType.Equals(type.FullName) || x.TargetType.Equals(type.Name));
        }

        public IEnumerable<RulePolicy> Policies(string route) {
            System.Diagnostics.Trace.WriteLine($"{DateTime.Now} RuleProvider.Rules(route) : Rule set fetched.");
            return PolicyCollection.Where(x => x.Route == "*" || x.Route.Equals(route, StringComparison.CurrentCultureIgnoreCase));
        }

        public IEnumerable<FilterPolicy> Filters(string type, ClaimsIdentity identity)
        {
            var filterPolicies  = PolicyCollection.Where(x => x.TargetType.Equals(type))
                .Where(x => x is FilterPolicy)
                .Cast<FilterPolicy>().ToList();

            var results = filterPolicies
                .Where(fp => fp.AppliesToIdentity(identity)).ToList();
            return results;
        }


        public IEnumerable<RulePolicy> Policies(string route, string method = "GET")
        {
            return PolicyCollection.Where(x => route.Like(x.Route)
                                               && method.Like(x.Action));
        }

        public void SetPolicies(IEnumerable<RulePolicy> policies) {
            PolicyCollection = policies;
        }
    }
}
