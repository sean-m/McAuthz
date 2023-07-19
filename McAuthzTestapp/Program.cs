using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Identity.Web;
using McAuthz;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Formatters;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

var builder = WebApplication.CreateBuilder(args);


// Add services to the container.

SMM.Assert.NotNull(builder.Configuration.GetSection("AzureAd"));
SMM.Assert.NotNull((string)builder.Configuration.GetValue(typeof(string), "AzureAd:Authority"));
SMM.Assert.NotNull((string)builder.Configuration.GetValue(typeof(string), "AzureAd:ClientSecret"));


builder.Services.AddLogging();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddMicrosoftIdentityWebApi(options =>
    {
        builder.Configuration.Bind("AzureAd", options);
        options.TokenValidationParameters.NameClaimType = "name";
    }, options => { builder.Configuration.Bind("AzureAd", options); });

builder.Services.AddAuthorization(config =>
{
    config.AddPolicy("AuthZPolicy", policyBuilder =>
        policyBuilder.Requirements.Add(new ScopeAuthorizationRequirement() { RequiredScopesConfigurationKey = $"AzureAd:Scopes" }));
});


//builder.Services.AddAuthentication(options => {
//    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
//})
//.AddJwtBearer(options => {
//    builder.Configuration.Bind("AzureAD", options);
//});

// McAuthorization Setup

var ruleProvider = new RuleProvider();
builder.Services.AddAuthorization(options => {
    options.AddPolicy(
        Globals.McPolicy, 
        policyBuilder => policyBuilder.AddRequirements(new RequireMcRuleApproved(ruleProvider.Rules))
    );
});
builder.Services.AddSingleton<IAuthorizationHandler, RequireMcRuleApprovedHandler>();



builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();


var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment()) {
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpLogging();
app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();
//app.UseMcRequestAuthorizationPolicy();

app.MapControllers();

app.Run();


public class RuleProvider {
    public List<ClaimRulePolicy> rules = new List<ClaimRulePolicy> {
        new ClaimRulePolicy(
            new[] { ("name", "Sean McArdle") })
    };

    public IEnumerable<ClaimRulePolicy> Rules () {
        System.Diagnostics.Trace.WriteLine($"{DateTime.Now} RuleProvider.Rules() : Rule set fetched.");
        return rules; 
    }
}