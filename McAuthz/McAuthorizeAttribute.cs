using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.AspNetCore.Authorization;

namespace McAuthz {
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]

    public class McAuthorizeAttribute : AuthorizeAttribute, IAuthorizeData {
        public McAuthorizeAttribute() { }
        
        public new string? Policy { get => Globals.McPolicy; set => _ = value; }
    }
}
