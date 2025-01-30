using Microsoft.AspNetCore.Http;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http.Internal;
using Microsoft.Extensions.Primitives;

namespace McAuthz.Tests
{
    public class MockHttpRequest : HttpRequest
    {
        private readonly HttpContext _httpContext;
        private readonly Dictionary<string, string> _headers = new Dictionary<string, string>();
        private readonly Dictionary<string, StringValues> _query = new Dictionary<string, StringValues>();
        private readonly Dictionary<string, string> _form = new Dictionary<string, string>();

        public MockHttpRequest(HttpContext httpContext)
        {
            _httpContext = httpContext;
            Query = new QueryCollection(_query);
        }

        public override HttpContext HttpContext => _httpContext;
        public override string Method { get; set; } = "GET";
        public override string Scheme { get; set; } = "http";
        public override bool IsHttps { get; set; } = false;
        public override HostString Host { get; set; } = new HostString("localhost");
        public override PathString PathBase { get; set; } = new PathString("/");
        public override PathString Path { get; set; } = new PathString("/");
        public override QueryString QueryString { get; set; } = new QueryString();
        public override IQueryCollection Query { get; set; }
        public override string Protocol { get; set; } = "HTTP/1.1";
        public override IHeaderDictionary Headers { get; } = new HeaderDictionary();
        public override IRequestCookieCollection Cookies { get; set; } = new RequestCookieCollection();
        public override long? ContentLength { get; set; }
        public override string ContentType { get; set; }
        public override Stream Body { get; set; } = new MemoryStream();
        public override bool HasFormContentType => true;
        public override IFormCollection Form { get; set; } = new FormCollection(new Dictionary<string, Microsoft.Extensions.Primitives.StringValues>());

        public override Task<IFormCollection> ReadFormAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Form);
        }
    }
}
