using McAuthz.Interfaces;
using McAuthz.Policy;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using McRule;

namespace McAuthz {
    public static class RuleProviderExtensions {

        public static Func<T, bool> Filters<T>(this IEnumerable<FilterPolicy> policies,
            ClaimsIdentity identity) {

            var result = new List<Func<T, bool>>();

            foreach (var rule in policies) {
                if (rule is FilterPolicy fp) {
                    var func = fp.GetFunc<T>(identity);
                    if (null != func) {
                        result.Add(func);
                    }
                }
            }

            if (result.Count() == 0) {
                return (T x) => false;
            }

            if (result.Count() == 1) {
                return result.First();
            }

            return result.Aggregate((a, b) => (x) => a(x) && b(x));
        }

        /// <summary>
        /// FiltersPolicies have lists of requirements, some of which match against a ClaimsIdentity
        /// to indicate whether the given policy should apply to that Identity, then additional requirements
        /// which match against properties of a given object to determine whether the policy should apply to that object.
        ///
        /// The list of requirements describes the association between the identity and an object.
        ///
        /// This function evaluates against the identity then returns the predicate for the object.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="provider"></param>
        /// <param name="identity"></param>
        /// <returns></returns>
        public static Func<T, bool> Filters<T>(this RuleProviderInterface provider,
            ClaimsIdentity identity) {
            var rules = provider.Filters(typeof(T).Name, identity);
            return rules.Filters<T>(identity);
        }

        /// <summary>
        /// ClaimsPrincipals may be comprised of multiple identities, if one of those identities
        /// is authorized to access a thing, then the ClaimsPrincipal should be authorized to access it.
        /// Rules for a given identity are evaluated with an 'and' operator, but aggregated with an 'or' across
        /// all identities.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="provider"></param>
        /// <param name="identity"></param>
        /// <returns></returns>
        public static Func<T, bool> Filters<T>(this RuleProviderInterface provider,
            ClaimsPrincipal identity) {
            var result = new List<Func<T, bool>>();

            foreach (ClaimsIdentity ci in identity.Identities) {
                var identityRule = Filters<T>(provider, ci);
                result.Add(identityRule);
            }

            if (result.Count() == 0) {
                return (T x) => false;
            }

            if (result.Count() == 1) {
                return result.First();
            }

            return result.Aggregate((a, b) => (x) => a(x) || b(x)); ;
        }
    }
}
