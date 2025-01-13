using McAttributes.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.OData.Routing.Controllers;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.OData;
using Newtonsoft.Json;
using System.Net;

using static McAuthz.Extensions;

namespace McAttributes.Controllers {
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class SayKVController : ODataController {
        private readonly ILogger<SayController> logger;
        private readonly IAuthorizationService authorizationService;

        public SayKVController(ILogger<SayController> logger, IAuthorizationService authorizationService) {
            this.logger = logger;
            this.authorizationService = authorizationService;
        }

        // GET: api/<SayController>
        [HttpGet]
        public IEnumerable<string> Get() {
            return new string[] { "value1", "value2" };
        }

        // GET api/<SayController>/5
        [HttpGet("{id}")]
        public string Get(int id) {
            return "value";
        }

        // POST api/<SayController>
        [HttpPost]
        public async Task<IActionResult> Post([FromBody] Dictionary<string,string> value) {
            value?.Upsert("#type", "Gossip");

            var authorizationResult = await authorizationService.McAuthorizeAsync(
                User, value, logger);
            if (!authorizationResult.Succeeded) {
                logger.LogWarning($"Gossip is unauthorized.\t{JsonConvert.SerializeObject(value)}");
                return Unauthorized();
            }

            logger.LogInformation($"Oh my! Hey {value["Recipient"]} did you hear about {value["Topic"]}?\n{JsonConvert.SerializeObject(value)}");
            return Ok();
        }

        // DELETE api/<SayController>/5
        [HttpDelete("{id}")]
        public async Task<IActionResult> Delete(int id) {
            var authorizationResult = await authorizationService.AuthorizeAsync(
            User, id, McAuthz.Globals.McPolicy);
            if (!authorizationResult.Succeeded) {
                return Unauthorized();
            }

            logger.LogInformation($"Delete: {id}");
            return Ok();
        }
    }
}
