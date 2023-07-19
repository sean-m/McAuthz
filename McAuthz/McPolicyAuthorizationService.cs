using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace McAuthz {
    public class McPolicyAuthorizationService : IAuthorizationService {

        ILogger _logger;
        PolicyRequestMapper _mapper;

        public McPolicyAuthorizationService(ILogger logger, PolicyRequestMapper mapper)
        {
            _logger = logger;
            _mapper = mapper;
        }

        public Task<AuthorizationResult> AuthorizeAsync(ClaimsPrincipal user, object? resource, IEnumerable<IAuthorizationRequirement> requirements) {
            throw new NotImplementedException();
        }

        public Task<AuthorizationResult> AuthorizeAsync(ClaimsPrincipal user, object? resource, string policyName) {
            throw new NotImplementedException();
        }
    }
}
