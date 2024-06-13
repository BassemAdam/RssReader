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
<div  id = "main" class= "col-lg-10 login-section">
<div  class="container-fluid mt-3">
    <div class="text-center">
        <h4 class="mt-1 mb-5 pb-1">Feed Real</h4>
    </div>
    <div class="row justify-content-center">
        <div class="col-12">
            <div class="card">
                <div class="row g-0">
                    <div class="col-md-6">
                        <div class="card-body">
                            <h2 class="card-title text-center">Login</h2>
                            <form id="login-section" hx-post="/login" hx-trigger="submit" hx-target="#main" hx-swap="outerHTML">
                                <div class="form-outline mb-4">
                                    <label class="form-label" for="form2Example11">Email</label>
                                    <input type="email" id="form2Example11" class="form-control" name="email" required />
                                </div>
                                <div class="form-outline mb-4">
                                    <label class="form-label" for="form2Example22">Password</label>
                                    <input type="password" id="form2Example22" class="form-control" name="password" required />
                                </div>
                                <input type="hidden" name="__RequestVerificationToken" value="{0}" />
                                <div class="text-center pt-1 mb-5 pb-1">
                                    <button type="submit" class="btn btn-primary btn-block" style='background: linear-gradient(to right, #ee7724, #d8363a, #dd3675, #b44593);'>Log in</button>
                                </div>
                                <div class="d-flex align-items-center justify-content-center pb-4 ">
                                    <p class="mb-0 me-2 m-2">Don't have an account?</p>
                                    <button hx-get="/signup-form" hx-swap="innerHTML" hx-target="#main" type="button" class="btn btn-outline-primary">Create new</button>
                                </div>
                            </form>
                        </div>
                    </div>
                    <div class="col-md-6 d-flex align-items-center" style="background: linear-gradient(to right, #ee7724, #d8363a, #dd3675, #b44593); border-radius: 0.3rem;">
                        <div class="text-white px-3 py-4 p-md-5 mx-md-4">
                            <h4 class="mb-4">Escape the Algorithm & Embrace the Clarity of RSS</h4>
                            <p class="small mb-0">In an age where social media algorithms dictate what we see, it's easy to become lost in a sea of targeted ads and manipulated content that aims to keep you engaging, not necessarily with important information or priorities, without you figuring it out. Break free from this cycle with RSS, a transparent and unbiased way to consume content. RSS feeds deliver the information you want, when you want it, without the interference of algorithms and ads. Join the movement to take back control of your media consumption and stay informed with pure, unfiltered content.</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
</ div >
""";



var signupHtml = """
<div id="main" class="card">
    <div class="card-body">
        <div class="text-center">
            <h4 class="mt-1 mb-5 pb-1">Feed Real</h4>
        </div>
        <div class="signup-header">
            <h2>Signup Form</h2>
        </div>
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
                <button hx-get='/login-form' hx-swap='outerHTML' hx-target='#main' type='button' data-mdb-button-init data-mdb-ripple-init class='btn btn-outline-primary'>Log in</button>
            </div>
        </form>
    </div>
</div>
""";

var feedPageHtml = @"
<div id='main'>
    <div class='container-fluid'>
        <div class='row'>
            <!-- Sidebar -->
            <div id='sidebar' class='bg-light border-right'>
                <div class='sidebar-heading p-3'>
                    Feed Real
                </div>
                <button hx-post='/logout' hx-target='#main' hx-swap='outerHTML' class='btn btn-danger m-3'>Logout</button>
                <form id='add-feed-form' hx-post='/feeds' hx-trigger='submit' hx-target='#responseMessage' hx-swap='afterend'>
                    <input type='hidden' name='__RequestVerificationToken' value='{0}' />
                    <div class='mb-3 p-3'>
                        <label for='feedUrl' class='form-label'>Feed URL</label>
                        <input type='text' class='form-control' id='feedUrl' name='Url' required>
                    </div>
                    <button type='submit' class='btn btn-primary m-3'>Add Feed</button>
                    <div id=""responseMessage""></div>
                </form>
                <div class='p-3'>
                    <h5>Select a feed to display on the page</h5>
                </div>
                <div id='feed-list' hx-get='/feeds-urls' hx-trigger='load' class='p-3'>
                    <!-- List of feeds will be dynamically loaded here -->
                </div>
            </div>
            <!-- Main content -->
            <div class='col p-3' style='transition: margin-left 0.5s;'>
                <div id='feeds'>
                    <!-- The feeds will be loaded here -->
                </div>
            </div>
        </div>
        <button id='sidebarToggle' class='btn btn-primary' style='background: linear-gradient(to right, #ee7724, #d8363a, #dd3675, #b44593);'>&#9776;</button>
    </div>
</div>
<script>
document.getElementById('sidebarToggle').addEventListener('click', function() {{
    var sidebar = document.getElementById('sidebar');
    var mainContent = document.querySelector('.col');
    var toggleButton = document.getElementById('sidebarToggle');
    if (sidebar.classList.contains('open')) {{
        sidebar.classList.remove('open');
        mainContent.classList.remove('col-expanded');
        toggleButton.style.left = '10px';
    }} else {{
        sidebar.classList.add('open');
        mainContent.classList.add('col-expanded');
        toggleButton.style.left = '340px';
    }}
}});
document.getElementById('feed-list').addEventListener('click', function(e) {{
    if (e.target.classList.contains('feed-url')) {{
        var selectedUrl = document.querySelector('.feed-url.selected');
        if (selectedUrl) {{
            selectedUrl.classList.remove('selected');
        }}
        e.target.classList.add('selected');
    }}
}});
</script>
";

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
    var successHtml = """
    <div id='success-message' class='alert alert-success' role='alert'>
        Signup successful!
    </div>
    <script>
        setTimeout(function() {{
            document.getElementById('success-message').style.display = 'none';
        }}, 3000); 
    </script>
    """;


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
            return Results.Content(html1, "text/html");

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
            new Claim(ClaimTypes.Name, user.email),
            new Claim(ClaimTypes.NameIdentifier, user.id.ToString()),
        };
        var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var authProperties = new AuthenticationProperties
        {
            IsPersistent = true,
            AllowRefresh = true
        };
        await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity), authProperties);
        context.Session.SetString("UserId", user.id.ToString());
    
        //var tokens = antiforgery.GetAndStoreTokens(context);
        //context.Response.Headers["X-CSRF-TOKEN"] = tokens.RequestToken;
        //var html = string.Format(feedPageHtml, tokens.RequestToken);
        return Results.Content(feedPageHtml, "text/html");
    }
    else
    {
        return Results.Content("Invalid email or password", "text/html");
    }
});


app.MapPost("/logout", async (HttpContext context,IAntiforgery antiforgery) =>
{
    var tokens = antiforgery.GetAndStoreTokens(context);
    context.Response.Headers["X-CSRF-TOKEN"] = tokens.RequestToken;

    context.Session.Clear();
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

    var html = string.Format(loginHtml, tokens.RequestToken);
    return Results.Content(html, "text/html");
 
});


app.MapPost("/feeds", async (HttpContext context, [FromForm] Feed feed) =>
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

        var successMessageHtml = @"
    <div id=""success-message"" class='alert alert-success' role='alert'>
      Feed URL has been added successfully!
    </div>
    <script>
        setTimeout(function() {{
            document.getElementById('success-message').style.display = 'none';
        }}, 3000); 
    </script>";

    return Results.Content(successMessageHtml, "text/html");
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
        //html.Append("<!DOCTYPE html><html lang='en'><head>");
        //html.Append("<meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>");
        //html.Append("<link href='https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css' rel='stylesheet'>");
        //html.Append("<title>RSS Feeds</title></head><body>");
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

app.MapGet("/getFeedData", async (HttpContext context, IDbConnection dbConnection, string url) =>
{
    if (string.IsNullOrEmpty(url))
    {
        return Results.BadRequest("Feed URL is required");
    }

    List<SyndicationItem> feedItems;
    SyndicationFeed syndicationFeed;
    try
    {
        using var reader = XmlReader.Create(url);
        syndicationFeed = SyndicationFeed.Load(reader);
        feedItems = syndicationFeed.Items.ToList();
    }
    catch (Exception ex)
    {
        return Results.BadRequest("Error reading feed: " + ex.Message);
    }

    var htmlBuilder = new StringBuilder();
    htmlBuilder.Append("<div class='container mt-5'>");

    // Add a header for all feeds with the channel name
    if (syndicationFeed.Title != null)
    {
        htmlBuilder.Append("<div class='row mb-4'>")
                   .Append("<div class='col-md-12'>")
                   .Append("<h1 class='display-4'>").Append(syndicationFeed.Title.Text).Append("</h1>")
                   .Append("</div>")
                   .Append("</div>");
    }

    foreach (var item in feedItems)
    {
        htmlBuilder.Append("<div class='row mb-4'>")
                   .Append("<div class='col-md-12'>")
                   .Append("<div class='card h-100'>");

        if (item.Title != null)
        {
            htmlBuilder.Append("<div class='card-header'>")
                       .Append("<h5 class='card-title font-weight-bold'>").Append(item.Title.Text).Append("</h5>")
                       .Append("</div>");
        }

        htmlBuilder.Append("<div class='card-body'>");

        var description = item.Summary?.Text ?? string.Empty;
        htmlBuilder.Append("<p class='card-text'>").Append(description).Append("</p>");

        if (item.Links.Any())
        {
            htmlBuilder.Append("<a href='").Append(item.Links.First().Uri.ToString()).Append("' class='btn btn-primary' target='_blank'>Read more</a>");
        }

        htmlBuilder.Append("</div>");

        // Handle publish date
        if (item.PublishDate != null)
        {
            string formattedDate;
            try
            {
                var publishDate = item.PublishDate.ToLocalTime(); // Convert to local time
                formattedDate = publishDate.ToString("f"); // Full (long) date and time pattern
            }
            catch (ArgumentOutOfRangeException)
            {
                formattedDate = "Unknown"; // Handle invalid date gracefully
            }

            htmlBuilder.Append("<div class='card-footer text-muted'>")
                       .Append("Published on: ").Append(formattedDate)
                       .Append("</div>");
        }

        htmlBuilder.Append("</div></div></div>");
    }

    htmlBuilder.Append("</div>");
    htmlBuilder.Append("<script src='https://code.jquery.com/jquery-3.5.1.slim.min.js'></script>");
    htmlBuilder.Append("<script src='https://cdn.jsdelivr.net/npm/@popperjs/core@2.5.2/dist/umd/popper.min.js'></script>");
    htmlBuilder.Append("<script src='https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js'></script>");

    return Results.Content(htmlBuilder.ToString(), "text/html");
});





app.MapGet("/feeds-urls", async (HttpContext context, IDbConnection dbConnection) =>
{
    var userId = context.Session.GetString("UserId");
    if (string.IsNullOrEmpty(userId))
    {
        return Results.BadRequest("User not logged in");
    }

    var feeds = await dbConnection.QueryAsync<Feed>("SELECT Url FROM Feeds WHERE UserId = @UserId", new { UserId = userId });
    var tokens = antiforgery.GetAndStoreTokens(context);
    context.Response.Headers["X-CSRF-TOKEN"] = tokens.RequestToken;

    var htmlBuilder = new StringBuilder();
    htmlBuilder.Append("<ul class='list-group'>");
    foreach (var feed in feeds)
    {
        htmlBuilder.AppendFormat(@"
            <li class='list-group-item d-flex justify-content-between align-items-center feed-url' data-url='{0}'>
                <span class='feed-url-text'>{0}</span>
                <form hx-delete='/feeds' hx-confirm='Are you sure you want to delete this feed?' hx-vals='{{""Url"":""{0}""}}' hx-target='closest li' hx-swap='outerHTML'>
                    <input type='hidden' name='__RequestVerificationToken' value='{1}' />
                    <button type='submit' class='btn btn-danger btn-sm delete-btn'>Delete</button>
                </form>
            </li>", feed.Url, tokens.RequestToken);
    }
    htmlBuilder.Append("</ul></div>");
    htmlBuilder.AppendFormat(@"
         <script>
        document.getElementById('feed-list').addEventListener('click', function(e) {{
            // Ignore clicks on the delete button
            if (e.target.classList.contains('delete-btn')) {{
                return;
            }}

            // Handle feed URL selection
            var feedUrlElement = e.target.closest('.feed-url');
            if (feedUrlElement) {{
                // Remove 'selected-feed' class from any previously selected URL
                var selectedFeed = document.querySelector('.selected-feed');
                if (selectedFeed) {{
                    selectedFeed.classList.remove('selected-feed');
                }}
                // Add 'selected-feed' class to the clicked URL
                feedUrlElement.classList.add('selected-feed');

                // Get the URL from the data-url attribute
                var feedUrl = feedUrlElement.getAttribute('data-url');

                // Use HTMX to send a request to /getFeedData with the selected URL
                // and replace the content of the main HTML element
                htmx.ajax('GET', '/getFeedData?url=' + encodeURIComponent(feedUrl), {{
                    target: '#feeds',
                    swap: 'outerHTML'
                }});
            }}
        }});
    </script>");

    return Results.Content(htmlBuilder.ToString(), "text/html");
});

app.MapDelete("/feeds", async (HttpContext context, IDbConnection dbConnection, IAntiforgery antiforgery) =>
{
    //try
    //{
    //    await antiforgery.ValidateRequestAsync(context);
    //}
    //catch (AntiforgeryValidationException)
    //{
    //    context.Response.StatusCode = 400;
    //    return Results.Content("Invalid anti-forgery token.");
    //}

    var form = await context.Request.ReadFormAsync();
    var url = form["Url"].ToString();

    if (string.IsNullOrEmpty(url)) return Results.BadRequest("Feed URL not provided");
    var userId = context.Session.GetString("UserId");
    if (string.IsNullOrEmpty(userId)) return Results.BadRequest("User not logged in");

    var user = await dbConnection.QueryFirstOrDefaultAsync<User>("SELECT * FROM Users WHERE Id = @UserId", new { UserId = userId });
    if (user == null) return Results.NotFound("User not found");

    await dbConnection.ExecuteAsync("DELETE FROM Feeds WHERE Url = @Url AND UserId = @UserId", new { Url = url, UserId = userId });
    return Results.Ok();
});

#endregion

app.Run();

