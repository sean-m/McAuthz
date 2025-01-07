
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

//builder.Services.AddAuthorization(options => {
//    options.AddPolicy(
//        Globals.McPolicy,
//        policyBuilder => policyBuilder.AddRequirements(
//            new RequireMcRuleApproved(ruleProvider))
//    );
//});
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

app.UseMcAuthorization();
app.UseAuthorization();

app.MapRazorPages();
app.MapControllers();

app.UseSwagger();
//app.UseSwaggerUI();


app.Run();



public class RuleProvider : RuleProviderInterface {

    private ILogger<RuleProvider>? logger;

    public RuleProvider() { }
    public RuleProvider(ILogger<RuleProvider> Logger) {
        logger = Logger;
    }

    internal IEnumerable<RulePolicy> ClaimRulesCollection { get; set; } = new List<RulePolicy> {
        new RequestPolicy(
            new Requirement[] {
                new ClaimRequirement ("name", "Sean McArdle"),
                new RoleRequirement ("Admin")
            }) {
            Name = "Sean with Admin role",
            Route = "/odata/User",
            Action = "GET"
        },
        new RequestPolicy(
            new Requirement[] {}) {
            Name = "All users can access the home page",
            Route = "/",
            Action = "GET",
            Authentication = AuthenticationStatus.Any
        },
    };

    internal Dictionary<Type, IEnumerable<RulePolicy>> ResourcePolicies { get; set; } = new Dictionary<Type, IEnumerable<RulePolicy>>();

    public IEnumerable<RulePolicy> Policies(string route, string method="GET") {
        logger?.LogInformation($"Getting claim policies for /{route} {method}");
        return ClaimRulesCollection.Where(x =>
            x.Route == "*"
            || x.Route.Equals(route, StringComparison.CurrentCultureIgnoreCase)
                && x.Action.Equals(method, StringComparison.CurrentCultureIgnoreCase));
    }

    public IEnumerable<RulePolicy> Policies(Type type) {
        if (ResourcePolicies.ContainsKey(type)) {
            logger?.LogInformation($"Getting type policies for {type.Name}");
            return ResourcePolicies[type];
        }

        logger?.LogWarning($"No policies for type:{type.Name}, returning empty set!");
        return Array.Empty<RulePolicy>();
    }
}