
using McAttributes;
using Microsoft.AspNetCore.OData;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using McAttributes.Data;
using McAttributes.Models;
using Microsoft.OData.Edm;
using Microsoft.OData.ModelBuilder;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using NuGet.Configuration;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Identity.Web;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web.UI;
using Microsoft.AspNetCore.Authorization;
using McAuthz;
using McAuthz.Policy;
using McAuthz.Interfaces;

static IEdmModel GetEdmModel() {
    var edmBuilder = new ODataConventionModelBuilder();
    var users = edmBuilder.EntitySet<User>("User");
    users.EntityType.Ignore(u => u.Pronouns);

    edmBuilder.EntitySet<IssueLogEntry>("IssueLogEntry");

    edmBuilder.EntitySet<Stargate>("Stargate");

    return edmBuilder.GetEdmModel();
}


var builder = WebApplication.CreateBuilder(args);

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

builder.Services.AddAuthorization(options => {
    options.AddPolicy(
        Globals.McPolicy,
        policyBuilder => policyBuilder.AddRequirements(new RequireMcRuleApproved(ruleProvider.Policies))
    );
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

// Updating an entity bombs without this. Postgresql requires UTC timestamps and for whatever
// reason, the default DateTime behavior is to just try shoving in a value with out a timezone.
AppContext.SetSwitch("Npgsql.EnableLegacyTimestampBehavior", true);

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

//app.UseMcAuthorization();

app.MapControllers();

app.UseRouting();

app.UseAuthorization();

app.MapRazorPages();
app.MapControllers();

app.UseSwagger();
//app.UseSwaggerUI();


app.Run();



public class RuleProvider : RuleProviderInterface {

    public IEnumerable<RulePolicy> RulesCollection { get; internal set; } = new List<RulePolicy> {
        new ClaimRulePolicy(
            new[] { ("~name", "~Sean McArdle") }) {
            Route = "User",
            Action = "GET"
        }
    };

    public IEnumerable<RulePolicy> Policies(string route, string action="GET") {
        System.Diagnostics.Trace.WriteLine($"{DateTime.Now} RuleProvider.Rules() : Rule set fetched.");
        return RulesCollection.Where(x =>
            x.Route == "*"
            || x.Route.Equals(route, StringComparison.CurrentCultureIgnoreCase)
                && x.Action.Equals(action, StringComparison.CurrentCultureIgnoreCase));
    }

    public IEnumerable<RulePolicy> Policies(Type type) {
        throw new NotImplementedException();
    }
}