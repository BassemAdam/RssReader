using Microsoft.AspNetCore.Builder;
using Microsoft.Data.Sqlite;
using Dapper;
using System.Data;
using RssReader.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;
using System.Collections.Generic;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Generators;
using System.Text;
using System.Xml;
using System.ServiceModel.Syndication;

#region services
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSingleton<IDbConnection>(sp => new SqliteConnection("Data Source=./wwwroot/RssReader.db"));

builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30); 
    options.Cookie.HttpOnly = true; 
    options.Cookie.IsEssential = true; 
});

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/login-form";
        options.LogoutPath = "/logout";
        options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
        options.SlidingExpiration = true;
    });
builder.Services.AddAuthorization();
builder.Services.AddAntiforgery(options => options.HeaderName = "X-CSRF-TOKEN");

#endregion

#region Application Middleware
var app = builder.Build();

app.UseStaticFiles();
app.UseSession();
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

#endregion

#region Initializion 
var antiforgery = app.Services.GetRequiredService<IAntiforgery>();
string DbPath = "Data Source=./wwwroot/RssReader.db";
#endregion

#region HtmlTemplates 
var loginHtml = """
<form id='login-section' hx-post='/login' hx-trigger='submit' hx-target='#main' hx-swap='outerHTML'>
    <div data-mdb-input-init class='form-outline mb-4'>
        <label class='form-label' for='form2Example11'>Email</label>
        <input type='email' id='form2Example11' class='form-control' name='email' />
    </div>
    <div data-mdb-input-init class='form-outline mb-4'>
        <label class='form-label' for='form2Example22'>Password</label>
        <input type='password' id='form2Example22' class='form-control' name='password' />
    </div>
    <input type='hidden' name='__RequestVerificationToken' value='{0}' />
    <div class='text-center pt-1 mb-5 pb-1'>
        <button type='submit' data-mdb-button-init data-mdb-ripple-init class='btn btn-primary btn-block fa-lg mb-3' style='background: linear-gradient(to right, #ee7724, #d8363a, #dd3675, #b44593);'>Log in</button>
    </div>
    <div class='d-flex align-items-center justify-content-center pb-4'>
        <p class='mb-0 me-2 mr-2'>Don't have an account?</p>
        <button hx-get='/signup-form' hx-swap='innerHTML' hx-target='#login-section' type='button' data-mdb-button-init data-mdb-ripple-init class='btn btn-outline-danger'>Create new</button>
    </div>
</form>
""";

var signupHtml = """
<form id='signup-section' hx-post='/signup' action='/signup' hx-vals='{{confirmPassword: null}}' hx-target='#response' hx-swap='innerHTML'>
    <div data-mdb-input-init class='form-outline mb-4'>
        <label class='form-label' for='form2Example11'>Email</label>
        <input type='email' id='form2Example11' class='form-control' name='email' />
    </div>
    <input type='hidden' name='__RequestVerificationToken' value='{0}' />
    <div data-mdb-input-init class='form-outline mb-4'>
        <label class='form-label' for='form2Example22'>Password</label>
        <input type='password' id='form2Example22' class='form-control' name='password' />
    </div>
    <div data-mdb-input-init class='form-outline mb-4'>
        <label class='form-label' for='form2Example33'>Confirm Password</label>
        <input type='password' id='form2Example33' class='form-control' name='confirmPassword' />
    </div>
    <div class='text-center pt-1 mb-5 pb-1'>
        <button type='submit' data-mdb-button-init data-mdb-ripple-init class='btn btn-primary btn-block fa-lg mb-3' style='background: linear-gradient(to right, #ee7724, #d8363a, #dd3675, #b44593);'>Sign Up</button>
    </div>
    <div id='response'></div>
    <div class='d-flex align-items-center justify-content-center pb-4'>
        <p class='mb-0 me-2 mr-2'>Already have an account?</p>
        <button hx-get='/login-form' hx-swap='innerHTML' hx-target='#signup-section' type='button' data-mdb-button-init data-mdb-ripple-init class='btn btn-outline-danger'>Log in</button>
    </div>
</form>
""";

var feedPageHtml = """
<div class='container'>
    <div class='row'>
        <div class='col-md-12'>
            <h1>RSS/ATOM Feeds</h1>
            <form hx-post='/feeds' hx-trigger='submit' hx-target='#feeds' hx-swap='outerHTML'>
                <input type='hidden' name='__RequestVerificationToken' value='{0}' />
                <div class='mb-3'>
                    <label for='feedUrl' class='form-label'>Feed URL</label>
                    <input type='text' class='form-control' id='feedUrl' name='Url' required>
                </div>
                <button type='submit' class='btn btn-primary'>Add Feed</button>
            </form>
        </div>
    </div>
    <div class='row'>
        <div class='col-md-12' id='feeds' hx-get='/feeds' hx-trigger='load'>
            <!-- The feeds will be loaded here -->
        </div>
    </div>
</div>
""";

var feedHtmlTemplate = """
    <div class='feed-url'>
        {0}
        <form hx-delete='/feeds' hx-confirm='Are you sure you want to delete this feed?' hx-headers='{{"X-CSRF-TOKEN":"{2}"}}' hx-target='.feed-url' hx-swap='outerHTML'>
            <input type='hidden' name='Url' value='{1}' />
            <button type='submit' class='btn btn-danger'>Delete</button>
        </form>
    </div>
""";
#endregion

#region APIs
app.MapGet("/signup-form", async (IAntiforgery antiforgery, HttpContext context) =>
{
    var tokens = antiforgery.GetAndStoreTokens(context);
    context.Response.Headers["X-CSRF-TOKEN"] = tokens.RequestToken;
    var html = string.Format(signupHtml, tokens.RequestToken);
    return Results.Content(html, "text/html");
});


app.MapPost("/signup", async (HttpContext context, [FromForm] UserInput userInput, IDbConnection connection, IAntiforgery antiforgery) =>
{
    try
    {
        await antiforgery.ValidateRequestAsync(context);
    }
    catch (AntiforgeryValidationException)
    {
        context.Response.StatusCode = 400;
        return Results.Content("Invalid anti-forgery token.");
    }
    string id = Guid.NewGuid().ToString();
    using (var dbConnection = new SqliteConnection("Data Source=./wwwroot/RssReader.db"))
    {
        await dbConnection.ExecuteAsync("INSERT INTO Users (id,email, password) VALUES (@id,@email, @password)", new { id = id, email = userInput.email, password = BCrypt.Net.BCrypt.HashPassword(userInput.password) });
    }
    var successHtml = @"
    <div id='success-message'>
        Signup successful! 
    </div>
    <script>
        setTimeout(function() {
            document.getElementById('success-message').style.display = 'none';
        }, 5000); // Hide the message after 5 seconds
    </script>";
    return Results.Content(successHtml, "text/html");
});


app.MapGet("/login-form", async (IAntiforgery antiforgery, HttpContext context, IDbConnection connection) =>
{
    // Check if the user is already authenticated
    var tokens = antiforgery.GetAndStoreTokens(context);
    context.Response.Headers["X-CSRF-TOKEN"] = tokens.RequestToken;
    if (context.User.Identity.IsAuthenticated)
    {
        var email = context.User.Identity.Name;
        var user = await connection.QuerySingleOrDefaultAsync<User>("SELECT * FROM Users WHERE email = @Email", new { Email = email });

        if (user != null)
        {
            var html1 = string.Format(feedPageHtml, tokens.RequestToken);
            return Results.Content($"authenticated:{html1}", "text/html");

        }
    }

    // User is not authenticated, return login form
    var html = string.Format(loginHtml, tokens.RequestToken);
    return Results.Content(html, "text/html");
});


app.MapPost("/login", async (HttpContext context, [FromForm] UserInput userInput, IAntiforgery antiforgery, IDbConnection connection) =>
{
    try
    {
        await antiforgery.ValidateRequestAsync(context);
    }
    catch (AntiforgeryValidationException)
    {
        context.Response.StatusCode = 400;
        return Results.Content("Invalid anti-forgery token.");
    }

    var user = await connection.QuerySingleOrDefaultAsync<User>("SELECT * FROM Users WHERE email = @Email", new { Email = userInput.email });

    if (user != null && BCrypt.Net.BCrypt.Verify(userInput.password, user.password))
    {
        
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.email)
        };
        var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        context.Session.SetString("UserId", user.id.ToString());
        await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity));
        var tokens = antiforgery.GetAndStoreTokens(context);
        context.Response.Headers["X-CSRF-TOKEN"] = tokens.RequestToken;
        var html = string.Format(feedPageHtml, tokens.RequestToken);
        return Results.Content(html, "text/html");
    }
    else
    {
        return Results.Content("Invalid email or password", "text/html");
    }
});


app.MapPost("/logout", async (HttpContext context) =>
{
    context.Session.Clear();
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Redirect("/login-form");
});


app.MapPost("/feeds", async (HttpContext context, [FromForm] Feed feed, IAntiforgery antiforgery) =>
{
    try
    {
        await antiforgery.ValidateRequestAsync(context);
    }
    catch (AntiforgeryValidationException)
    {
        context.Response.StatusCode = 400;
        return Results.Content("Invalid anti-forgery token.");
    }
    var userId = context.Session.GetString("UserId");
    if (string.IsNullOrEmpty(userId)) return Results.BadRequest("User not logged in");
    using (var dbConnection = new SqliteConnection("Data Source=./wwwroot/RssReader.db"))
    {
        var user = await dbConnection.QueryFirstOrDefaultAsync<User>("SELECT * FROM Users WHERE Id = @UserId", new { UserId = userId });
        if (user == null) return Results.NotFound("User not found");
        await dbConnection.ExecuteAsync("INSERT INTO Feeds (Url, UserId) VALUES (@Url, @UserId)", new { feed.Url, UserId = userId });
    }

    var tokens = antiforgery.GetAndStoreTokens(context);
    var realToken = tokens.RequestToken;

    
 
    var html = string.Format(feedHtmlTemplate, feed.Url, feed.Url, realToken);
    return Results.Content(html.ToString(), "text/html");
});
app.MapGet("/feeds", async (HttpContext context, IDbConnection connection) =>
{

    var email = context.User.Identity.Name;
    using (var dbConnection = new SqliteConnection("Data Source=./wwwroot/RssReader.db"))
    {
        var user = await dbConnection.QueryFirstOrDefaultAsync<User>("SELECT * FROM Users WHERE email = @Email", new { Email = email });
        if (user == null) return Results.NotFound("User not found");

        var feeds = await connection.QueryAsync<Feed>("SELECT * FROM Feeds WHERE UserId = @UserId", new { UserId = user.id });

        var feedItems = new List<SyndicationItem>();
        foreach (var feed in feeds)
        {
            using var reader = XmlReader.Create(feed.Url);
            var syndicationFeed = SyndicationFeed.Load(reader);
            feedItems.AddRange(syndicationFeed.Items);
        }

        var html = new StringBuilder();
        html.Append("<!DOCTYPE html><html lang='en'><head>");
        html.Append("<meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>");
        html.Append("<link href='https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css' rel='stylesheet'>");
        html.Append("<title>RSS Feeds</title></head><body>");
        html.Append("<div class='container mt-5'><div class='row'>");

        foreach (var item in feedItems)
        {
            html.Append("<div class='col-md-4'><div class='card mb-3'>");

            if (item.Title != null)
            {
                html.Append("<div class='card-header'>").Append(item.Title.Text).Append("</div>");
            }

            var link = item.Links.FirstOrDefault()?.Uri.ToString();
            if (link != null && Uri.IsWellFormedUriString(link, UriKind.Absolute))
            {
                html.Append("<img class='card-img-top' src='").Append(link).Append("' alt='Feed Image' />");
            }

            var description = item.Summary?.Text ?? string.Empty;
            html.Append("<div class='card-body'><p class='card-text'>").Append(description).Append("</p></div>");

            if (item.Links.Any())
            {
                html.Append("<div class='card-footer'><a href='").Append(item.Links.First().Uri.ToString()).Append("' class='btn btn-primary'>Read more</a></div>");
            }

            html.Append("</div></div>");
        }

        html.Append("</div></div>");
        html.Append("<script src='https://code.jquery.com/jquery-3.5.1.slim.min.js'></script>");
        html.Append("<script src='https://cdn.jsdelivr.net/npm/@popperjs/core@2.5.2/dist/umd/popper.min.js'></script>");
        html.Append("<script src='https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js'></script>");
        html.Append("</body></html>");

        return Results.Content(html.ToString(), "text/html");
    }
});

app.MapDelete("/feeds", async (HttpContext context, IDbConnection dbConnection, IAntiforgery antiforgery) =>
{
    try
    {
        await antiforgery.ValidateRequestAsync(context);
    }
    catch (AntiforgeryValidationException)
    {
        context.Response.StatusCode = 400;
        return Results.Content("Invalid anti-forgery token.");
    }

    var form = await context.Request.ReadFormAsync();
    var url = form["Url"].ToString();

    if (string.IsNullOrEmpty(url)) return Results.BadRequest("Feed URL not provided");
    var userId = context.Session.GetString("UserId");
    if (string.IsNullOrEmpty(userId)) return Results.BadRequest("User not logged in");

    var user = await dbConnection.QueryFirstOrDefaultAsync<User>("SELECT * FROM Users WHERE Id = @UserId", new { UserId = userId });
    if (user == null) return Results.NotFound("User not found");

    await dbConnection.ExecuteAsync("DELETE FROM Feeds WHERE Url = @Url AND UserId = @UserId", new { Url = url, UserId = userId });
    return Results.Ok("Feed deleted successfully");
});

#endregion

app.Run();

