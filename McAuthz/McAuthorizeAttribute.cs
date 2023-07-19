using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.AspNetCore.Authorization;

namespace McAuthz {
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]

    public class McAuthorizeAttribute : AuthorizeAttribute, IAuthorizeData {
        public McAuthorizeAttribute() { }
        public McAuthorizeAttribute(string route) {
            Route = route;
        }

        /// <summary>
        /// The route associated with the given authorization policy. This allows
        /// targetting specific policies per web api, mvc or razor pages route.
        /// </summary>
        public string? Route { get; set; }

        public new string Policy { get => Globals.McPolicy; set => _ = value; }
    }
}
