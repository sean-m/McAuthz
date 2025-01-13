
using McAttributes;
using McAttributes.Data;
using McAttributes.Models;
using McAuthz;
using McAuthz.Interfaces;
using McAuthz.Policy;
using McAuthz.Requirements;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.OData;
using Microsoft.EntityFrameworkCore;
using Microsoft.Identity.Web.UI;
using Microsoft.OData.Edm;
using Microsoft.OData.ModelBuilder;
using System.Data;

static IEdmModel GetEdmModel() {
    var edmBuilder = new ODataConventionModelBuilder();
    var users = edmBuilder.EntitySet<User>("User");
    users.EntityType.Ignore(u => u.Pronouns);

    edmBuilder.EntitySet<IssueLogEntry>("IssueLogEntry");

    edmBuilder.EntitySet<Stargate>("Stargate");

    return edmBuilder.GetEdmModel();
}


var builder = WebApplication.CreateBuilder(args);


// Logging
builder.Services.AddLogging(options => {
    options.AddConsole();
    options.SetMinimumLevel(Microsoft.Extensions.Logging.LogLevel.Information);
});


// Add and load configuration sources.
#pragma warning disable ASP0013 // Suggest switching from using Configure methods to WebApplicationBuilder.Configuration
builder.Host.ConfigureAppConfiguration((hostingContext, config) => {
    config.Sources.Clear();

    var env = hostingContext.HostingEnvironment;
    config.AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
          .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true, reloadOnChange: true);

    config.AddEnvironmentVariables();

    // NOTE: set the connection string value in an environment variable or appsettings json file with key: AppConfigConnectionString
    //var configString = builder.Configuration.GetValue<string>("AppConfigConnectionString");
    //config.AddAzureAppConfiguration(configString);

    // Add command line args last so they can override anything else.
    if (args != null) {
        config.AddCommandLine(args);
    }
});
#pragma warning restore ASP0013 // Suggest switching from using Configure methods to WebApplicationBuilder.Configuration


builder.Services.AddAuthentication(options => {
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddOpenIdConnect(options => {
    builder.Configuration.Bind("AzureAD", options);
})
.AddJwtBearer(options => {
    builder.Configuration.Bind("AzureAD", options);
})
.AddCookie();


builder.Services.AddRazorPages()
    .AddMicrosoftIdentityUI(); ;


var ruleProvider = new RuleProvider();

builder.Services.AddSingleton<RuleProviderInterface>(ruleProvider);
builder.Services.AddSingleton<PolicyRequestMapper>();
// This is used for resource authorization rules. That is policies that inspect the resources which are handled in the controller.
builder.Services.AddAuthorization(options => {
    options.AddPolicy(
        Globals.McPolicy,
        policyBuilder => policyBuilder.Requirements.Add(
            new RequireMcRuleApproved(ruleProvider))
    );
    options.FallbackPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
});
builder.Services.AddSingleton<IAuthorizationHandler, RequireMcRuleApprovedHandler>();


// Add services to the container.
builder.Services.AddControllers()
    .AddNewtonsoftJson()
    .AddOData(
        options => options.AddRouteComponents("odata", GetEdmModel())
            .EnableQueryFeatures(maxTopValue: 500));


// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(
    opt => opt.ResolveConflictingActions(a => a.First()));
builder.Logging.AddConsole();



var connString = "Data Source=test.db";
builder.Services.AddDbContext<IdDbContext>(
    options => { options.UseSqlite(connString); });

var app = builder.Build();


using (IServiceScope serviceScope = app.Services.GetService<IServiceScopeFactory>().CreateScope())
{
    var idDbContext = serviceScope.ServiceProvider.GetRequiredService<IdDbContext>();
    if (idDbContext.Database.EnsureCreated()) {
        if (!builder.Environment.IsProduction()) {
            // Initialize the database with test data when running in
            // debug mode and having just created tables.
            System.Diagnostics.Trace.WriteLine("Initialized database tables. Loading table data from test_values.csv.");
            DebugInit.DbInit(idDbContext);
        }
    }
}


// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment()) {
    app.UseDeveloperExceptionPage();
}

//app.UseAzureAppConfiguration();
app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseAuthentication();

app.MapControllers();
app.UseRouting();

app.UseAuthorization();
app.UseMcAuthorization();

app.MapRazorPages();
app.MapControllers();

app.UseSwagger();
//app.UseSwaggerUI();


app.Run();



public class RuleProvider : RuleProviderInterface {

    private ILogger<RuleProvider>? logger;

    public RuleProvider() { initResourcePolicies(); }
    public RuleProvider(ILogger<RuleProvider> Logger) {
        logger = Logger;
        initResourcePolicies();
    }

    internal IEnumerable<RulePolicy> RequestPolicies { get; set; } = new List<RulePolicy> {
        new RequestPolicy(
            new Requirement[] {
                new ClaimRequirement ("name", "Sean McArdle"),
                new RoleRequirement ("Admin"),
            }) {
            Name = "Sean with Admin role",
            Route = "/odata/User",
            Action = "GET"
        },
        new RequestPolicy() {
            Name = "All users can access the home page",
            Route = "/",
            Action = "GET",
            Authentication = AuthenticationStatus.Any
        },
        new RequestPolicy() {
            Name = "All users can access shared www resources",
            Route = "/Shared/*",
            Action = "GET",
            Authentication = AuthenticationStatus.Any
        },
        new RequestPolicy() {
            Name = "All users access /MicrosoftIdentity/*",
            Route = "/MicrosoftIdentity/*",
            Action = "*",
            Authentication = AuthenticationStatus.Any
        },
        RequestPolicy.FromJson("{'Name':'Allow authenticated to Stargate','Route':'/odata/Stargate','Action':'GET','Authentication':'Authenticated'}"),
        new RequestPolicy(
            new Requirement[] {
                new ClaimRequirement ("name", "Sean McArdle"),
                new RoleRequirement ("Admin")
            }) {
            Name = "Say: Sean with Admin role",
            Route = "/*/Say",
            Action = "GET"
        },
        new RequestPolicy(
            new Requirement[] {
                new ClaimRequirement ("name", "Sean McArdle"),
                new RoleRequirement ("Admin")
            }) {
            Name = "Say: Sean with Admin role",
            Route = "/*/Say*",
            Action = "P*T"
        },
    };

    internal Dictionary<string, List<RulePolicy>> ResourcePolicies { get; set; } = new Dictionary<string, List<RulePolicy>>(
        StringComparer.CurrentCultureIgnoreCase);

    private IEnumerable<ResourceRulePolicy> _policies { get; set; } = new[] {
        new ResourceRulePolicy()
        {
            Requirements = new Requirement[] {
                new PropertyRequirement ("name", "John Doe"),
                new PropertyRequirement ("topic", "Office News"),
            },
            Name = "KV Gossip allowed for John Doe",
            TargetType = "Gossip"
        },
    };


    void initResourcePolicies() {
        foreach (var r in _policies) {
            if (!ResourcePolicies.ContainsKey(r.TargetType)) {
                ResourcePolicies.Add(r.TargetType, new List<RulePolicy>());
            }

            ResourcePolicies[r.TargetType].Add(r);
        }
    }

    public IEnumerable<RulePolicy> Policies(string route, string method="GET") {
        logger?.LogInformation($"Getting claim policies for /{route} {method}");
        return RequestPolicies.Where(x => route.Like(x.Route)
                && method.Like(x.Action));
    }

    public IEnumerable<RulePolicy> Policies(string type) {
        if (ResourcePolicies.ContainsKey(type)) {
            logger?.LogInformation($"Getting type policies for {type}");
            return ResourcePolicies[type];
        }

        logger?.LogWarning($"No policies for type:{type}, returning empty set!");
        return Array.Empty<RulePolicy>();
    }
}
public static class DictionaryExtensions {
    public static void Upsert(this Dictionary<string, string> dict, string key, string value) {
        if (string.IsNullOrEmpty(key)) return;

        if (dict.ContainsKey(key)) {
            dict[key] = value;
        } else {
            dict.Add(key, value);
        }
    }

    public static void Upsert<T>(this Dictionary<string, T> dict, string key, T value) {
        if (string.IsNullOrEmpty(key)) return;

        if (dict.ContainsKey(key)) {
            dict[key] = value;
        } else {
            dict.Add(key, value);
        }
    }

    public static void Upsert<T>(this Dictionary<string, List<T>> dict, string key, T value) {
        if (string.IsNullOrEmpty(key)) return;

        if (dict.ContainsKey(key)) {
            dict[key].Add(value);
        } else {
            dict.Add(key, new List<T> { value });
        }
    }
}