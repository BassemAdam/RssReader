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
using BCrypt.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Components.Forms;
using System.Text.Json;

#region services
var builder = WebApplication.CreateBuilder(args);
var connectionString = builder.Configuration.GetConnectionString("RssReaderDb");
builder.Services.AddScoped<IDbConnection>(sp => new SqliteConnection(connectionString));
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
        options.Cookie.HttpOnly = true; 
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always; 
        options.Cookie.SameSite = SameSiteMode.Strict; 
    });
builder.Services.AddAuthorization();
builder.Services.AddAntiforgery();
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
#endregion

#region HTML templates
var loginHtml = @"
<div id=""main"" class=""col-lg-10 login-section"">
    <div class=""container-fluid mt-3"">
        <div class=""text-center"">
            <h4 class=""mt-1 mb-5 pb-1"">Feed Real</h4>
        </div>
        <div class=""row justify-content-center"">
            <div class=""col-12"">
                <div class=""card"">
                    <div class=""row g-0"">
                        <div class=""col-md-6"">
                            <div class=""card-body"">
                                <h2 class=""card-title text-center"">Login</h2>
                                <form id=""login-section"" hx-post=""/login"" hx-trigger=""submit"" hx-target=""#main"" hx-boost=""true"" hx-swap=""outerHTML"" data-parsley-validate>
                                    <div class=""form-outline mb-4"">
                                        <label class=""form-label"" for=""loginEmail"">Email</label>
                                        <input type=""email"" id=""loginEmail"" class=""form-control"" name=""email"" required required data-parsley-trigger=""change"" data-parsley-required-message=""Email is required"" data-parsley-type-message=""Please enter a valid email address"" />
                                        <div id=""loginEmailError"" class=""text-danger""></div>
                                    </div>
                                    <div class=""form-outline mb-4"">
                                        <label class=""form-label"" for=""loginPassword"">Password</label>
                                        <input type=""password"" id=""loginPassword"" class=""form-control"" name=""password"" required minlength=""8"" data-parsley-trigger=""change"" data-parsley-required-message=""Password is required"" />
                                        <div id=""loginPasswordError"" class=""text-danger""></div>
                                    </div>
                                    <input type=""hidden"" name=""__RequestVerificationToken"" value=""{0}"" />
                                    <div class=""text-center pt-1 mb-5 pb-1"">
                                        <button type=""submit"" class=""btn btn-primary btn-block"" style=""background: linear-gradient(to right, #ee7724, #d8363a, #dd3675, #b44593);"">Log in</button>
                                    </div>
                                    <div id=""loginError"" ></div>
                                    <div class=""d-flex align-items-center justify-content-center pb-4"">
                                        <p class=""mb-0 me-2 m-2"">Don't have an account?</p>
                                        <button hx-get=""/signup-form"" hx-swap=""innerHTML"" hx-target=""#main"" type=""button"" class=""btn btn-outline-primary"">Create new</button>
                                    </div>
                                </form>
                            </div>
                              
                        </div>
                        <div class=""col-md-6 d-flex align-items-center"" style=""background: linear-gradient(to right, #ee7724, #d8363a, #dd3675, #b44593); border-radius: 0.3rem;"">
                            <div class=""text-white px-3 py-4 p-md-5 mx-md-4"">
                                <h4 class=""mb-4"">Escape the Algorithm & Embrace the Clarity of RSS</h4>
                                <p class=""small mb-0"">In an age where social media algorithms dictate what we see, it's easy to become lost in a sea of targeted ads and manipulated content that aims to keep you engaging, not necessarily with important information or priorities, without you figuring it out. Break free from this cycle with RSS, a transparent and unbiased way to consume content. RSS feeds deliver the information you want, when you want it, without the interference of algorithms and ads. Join the movement to take back control of your media consumption and stay informed with pure, unfiltered content.</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
<script>
     $(document).ready(function() {{
         $('#login-section button[type=""submit""]').attr('disabled', true);
         $('#login-section').parsley().on('field:validated', function() {{
             var ok = $('.parsley-error').length === 0 && $('#login-section').parsley().isValid();
             $('#login-section button[type=""submit""]').attr('disabled', !ok);
         }}).on('form:submit', function() {{
             return true; 
         }});
     }});
 document.body.addEventListener('htmx:afterRequest', function(event) {{
        if (event.detail.xhr.status === 400) {{
            var loginErrorDiv = document.getElementById('loginError');
            loginErrorDiv.innerHTML = event.detail.xhr.responseText;
        }}
    }});
   document.body.addEventListener('htmx:afterOnLoad', function(event) {{
        var alertDiv = document.getElementById('loginError1');
        if (alertDiv) {{
            setTimeout(function() {{
                alertDiv.style.display = 'none';
            }}, 3000);
        }}
    }});
</script>
";

var signupHtml = @"
<div id=""main"" class=""card"">
    <div class=""card-body"">
        <div class=""text-center"">
            <h4 class=""mt-1 mb-5 pb-1"">Feed Real</h4>
        </div>
        <div class=""signup-header"">
            <h2>Signup Form</h2>
        </div>
        <form id=""signup-section"" hx-post=""/signup"" action=""/signup"" hx-vals=""{{confirmPassword: null}}"" hx-target=""#response"" hx-swap=""innerHTML"" data-parsley-validate>
            <div data-mdb-input-init class=""form-outline mb-4"">
                <label class=""form-label"" for=""signupEmail"">Email</label>
                <input type=""email"" id=""signupEmail"" class=""form-control"" name=""email"" required data-parsley-trigger=""change"" data-parsley-required-message=""Email is required"" data-parsley-type-message=""Please enter a valid email address""/>
                <div id=""signupEmailError"" class=""text-danger""></div>
            </div>
            <input type=""hidden"" name=""__RequestVerificationToken"" value=""{0}"" />
            <div data-mdb-input-init class=""form-outline mb-4"">
                <label class=""form-label"" for=""signupPassword"">Password</label>
                <input type=""password"" id=""signupPassword"" class=""form-control"" name=""password"" required minlength=""8"" data-parsley-trigger=""change"" data-parsley-required-message=""password is required"" />
                <div id=""signupPasswordError"" class=""text-danger""></div>
            </div>
            <div data-mdb-input-init class=""form-outline mb-4"">
                <label class=""form-label"" for=""confirmPassword"">Confirm Password</label>
                <input type=""password"" id=""confirmPassword"" class=""form-control"" name=""confirmPassword"" required data-parsley-equalto=""#signupPassword"" data-parsley-trigger=""change"" data-parsley-required-message=""password is required""/>
                <div id=""confirmPasswordError"" class=""text-danger""></div>
            </div>
            <div class=""text-center pt-1 mb-5 pb-1"">
                <button type=""submit"" data-mdb-button-init data-mdb-ripple-init class=""btn btn-primary btn-block fa-lg mb-3"" style=""background: linear-gradient(to right, #ee7724, #d8363a, #dd3675, #b44593);"" disabled>Sign Up</button>
            </div>
            <div id=""response""></div>
            <div class=""d-flex align-items-center justify-content-center pb-4"">
                <p class=""mb-0 me-2 mr-2"">Already have an account?</p>
                <button hx-get=""/login-form"" hx-swap=""outerHTML"" hx-target=""#main"" type=""button"" data-mdb-button-init data-mdb-ripple-init class=""btn btn-outline-primary"">Log in</button>
            </div>
        </form>
    </div>
</div>
<script>
     $(document).ready(function() {{
        function updateSubmitButtonState() {{
            var formIsValid = $('#signup-section').parsley().isValid();
            $('#signup-section button[type=""submit""]').attr('disabled', !formIsValid);
        }}
        $('#signup-section').parsley();
        $('#signup-section').parsley().on('field:validated', function() {{
            updateSubmitButtonState();
        }});
        $('#signup-section').parsley().on('form:validated', function() {{
            updateSubmitButtonState();
        }});
        updateSubmitButtonState();
    }});
</script>
";

var feedPageHtml = @"
    <div id='main'>
        <div class='container-fluid'>
            <div class='row'>
                <div id='sidebar' class='bg-light border-right open'>
                    <div class='sidebar-heading p-3'>
                        Feed Real
                    </div>
                    <button hx-post='/logout' hx-target='#main' hx-swap='outerHTML' class='btn btn-danger m-3'>Logout</button>
                    <form id='add-feed-form' hx-post='/feeds' hx-trigger='submit' hx-target='#feed-list' hx-swap='innerHTML'>
                        <input type='hidden' name='__RequestVerificationToken' value='{0}' />
                        <div class='mb-3 p-3'>
                            <label for='feedUrl' class='form-label'>Feed URL</label>
                            <input type='text' class='form-control' id='feedUrl' name='Url' required pattern=""https?://.*\.xml$"">
                            <div id='feedUrlError' class='text-danger'></div>
                        </div>
                        <button type='submit' class='btn btn-primary m-3' id='addFeedButton'>Add Feed</button>
                        <div id='responseMessage'></div>
                    </form>
               <div class='d-flex justify-content-center align-items-center'>
                    <form id=""generate-share-link-form"" class=""mb-4"" onsubmit=""return false;"">
                        <button type=""submit"" class=""btn btn-primary"" onclick=""generateAndCopyLink()"">Generate Shareable Link</button>
                    </form>
                </div>
                <div id=""share-link-container""></div>
                    <div class='p-3'>
                        <h5>Select a feed to display on the page</h5>
                    </div>
                    <div id='feed-list' hx-get='/feeds-urls' hx-trigger='load' class='p-3'>
                    </div>
                </div>
                <div class='col p-3 col-expanded' style='transition: margin-left 0.5s;'>
                    <div id='feeds'>
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
    function generateAndCopyLink() {{
        fetch('/generate-share-link', {{
            method: 'POST',
            headers: {{
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            }},
        }})
        .then(response => response.text()) 
        .then(link => {{
            navigator.clipboard.writeText(link).then(() => {{
                const expirationDate = new Date();
                expirationDate.setDate(expirationDate.getDate() + 7);
                alert(`Share link copied to clipboard. The link will expire on ${{expirationDate.toLocaleDateString()}}.`);
            }}).catch(err => {{
                console.error('Could not copy text: ', err);
            }});
        }})
        .catch(error => console.error('Error generating share link:', error));
    }}
    document.addEventListener('DOMContentLoaded', function() {{
        const feedUrlInput = document.getElementById('feedUrl');
        const addFeedButton = document.getElementById('addFeedButton');
        const feedUrlError = document.getElementById('feedUrlError');

        function validateFeedUrl() {{
            if (!feedUrlInput.checkValidity()) {{
                if(feedUrlInput.validity.patternMismatch) {{
                    feedUrlError.textContent = 'Please enter a valid RSS feed URL that ends with .xml.';
                }} else if(feedUrlInput.validity.valueMissing) {{
                    feedUrlError.textContent = 'This field is required.';
                }} else {{
                    feedUrlError.textContent = 'Invalid input.';
                }}
                addFeedButton.disabled = true;
            }} else {{
                feedUrlError.textContent = '';
                addFeedButton.disabled = false;
            }}
        }}

    feedUrlInput.addEventListener('input', validateFeedUrl);
    validateFeedUrl();
    }});
    </script>
    ";
#endregion

#region Utility Methods
static bool IsRtlContent(string text)
{
    if (string.IsNullOrEmpty(text))
    {
        return false;
    }

    int[][] rtlRanges = new int[][]
    {
        new int[] { 0x0590, 0x05FF }, // Hebrew
        new int[] { 0x0600, 0x06FF }, // Arabic
        new int[] { 0x0750, 0x077F }, // Arabic Supplement
        new int[] { 0x08A0, 0x08FF }, // Arabic Extended-A
        new int[] { 0xFB50, 0xFDFF }, // Arabic Presentation Forms-A
        new int[] { 0xFE70, 0xFEFF }, // Arabic Presentation Forms-B
        new int[] { 0x0700, 0x074F }, // Syriac
        new int[] { 0x0780, 0x07BF }, // Thaana
        new int[] { 0x07C0, 0x07FF }, // NKo
        new int[] { 0x0800, 0x083F }, // Samaritan
        new int[] { 0x0840, 0x085F }, // Mandaic
        new int[] { 0x0860, 0x086F }  // Syriac Supplement
    };

    foreach (char c in text)
    {
        int codePoint = (int)c;
        if (rtlRanges.Any(range => codePoint >= range[0] && codePoint <= range[1]))
        {
            return true;
        }
    }

    return false;
}
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
    if (context.User.Identity.IsAuthenticated)
    {
        var email = context.User.Identity.Name;
        var user = await connection.QuerySingleOrDefaultAsync<User>("SELECT * FROM Users WHERE email = @Email", new { Email = email });

        if (user != null)
        {
           context.Session.SetString("UserId", user.id.ToString());

            var tokens = antiforgery.GetAndStoreTokens(context);
            var html = string.Format(feedPageHtml, tokens.RequestToken);
            return Results.Content(html, "text/html");
        }
    }
    var tokens1 = antiforgery.GetAndStoreTokens(context);
    var html1 = string.Format(loginHtml, tokens1.RequestToken);
    return Results.Content(html1, "text/html");
});

app.MapPost("/login", [ValidateAntiForgeryToken] async (HttpContext context, [FromForm] UserInput userinput, IAntiforgery antiforgery, IDbConnection connection) =>
{
    var user = await connection.QuerySingleOrDefaultAsync<User>("SELECT * FROM Users WHERE email = @Email", new { Email = userinput.email });

    if (user != null && BCrypt.Net.BCrypt.Verify(userinput.password, user.password))
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
        return Results.Redirect("/login-form");
    }
    else
    {
        context.Response.StatusCode = 400; 
        context.Response.ContentType = "text/plain";
        return Results.Content("<div id=\"loginError1\" class=\"alert alert-danger\" role=\"alert\">Invalid email or password</div>", "text/html");
    }

});

app.MapPost("/logout", async (HttpContext context) =>
{
    context.Session.Clear();
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Redirect("/login-form");
});

app.MapPost("/feeds", [ValidateAntiForgeryToken] async (HttpContext context, [FromForm] Feed feed ,IAntiforgery antiforgery ) =>
{
    var userId = context.Session.GetString("UserId");
    if (string.IsNullOrEmpty(userId)) return Results.BadRequest("User not logged in");
    using (var dbConnection = new SqliteConnection("Data Source=./wwwroot/RssReader.db"))
    {
        var user = await dbConnection.QueryFirstOrDefaultAsync<User>("SELECT * FROM Users WHERE Id = @UserId", new { UserId = userId });
        if (user == null) return Results.NotFound("User not found");
        await dbConnection.ExecuteAsync("INSERT INTO Feeds (Url, UserId) VALUES (@Url, @UserId)", new { feed.Url, UserId = userId });
    }
    return Results.Redirect("/feeds-urls");
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
        feedItems = feedItems.OrderByDescending(item => item.PublishDate).ToList();

        var html = new StringBuilder();
        html.Append("<div class='container-fluid mt-5' style='padding: 0 15px;'>");

       
        html.Append("<div class='row mb-4 justify-content-center'>")
            .Append("<div class='col-12 col-md-10 col-lg-8'>")
            .Append("<h1 class='display-4 text-center' style='font-size: 2.5rem;'>All Feeds</h1>")
            .Append("</div>")
            .Append("</div>");

        foreach (var item in feedItems)
        {
            bool isRtlContent = IsRtlContent(item.Summary.Text); 

            var cardClass = isRtlContent ? "card rtl" : "card";
            html.Append($"<div class='row mb-4 justify-content-center'>")
           .Append($"<div class='col-12 col-md-10 col-lg-8'>")
           .Append($"<div class='{cardClass}' style='word-wrap: break-word;'>");

            if (item.Title != null)
            {
                html.Append("<div class='card-header'>")
                    .Append("<h5 class='card-title font-weight-bold text-center' style='font-size: 1.25rem;'>").Append(item.Title.Text).Append("</h5>")
                    .Append("</div>");
            }

            html.Append("<div class='card-body'>");

            var description = item.Summary?.Text ?? string.Empty;
            description = Regex.Replace(description, "<iframe(.+?)</iframe>", "<div class='video-container'><iframe$1</iframe></div>", RegexOptions.IgnoreCase | RegexOptions.Singleline);
            description = description.Replace("<img ", "<img style='max-width:100%;height:auto;' ");

            html.Append("<p class='card-text'>").Append(description).Append("</p>");
            html.Append("</div>");
            html.Append("<div class='card-footer text-muted d-flex flex-wrap justify-content-between align-items-center'>");
            if (item.PublishDate != null)
            {
                string formattedDate;
                try
                {
                    var publishDate = item.PublishDate.ToLocalTime(); 
                    formattedDate = publishDate.ToString("f"); 
                }
                catch (ArgumentOutOfRangeException)
                {
                    formattedDate = "Unknown"; 
                }
                html.Append("<div class='col-12 col-md-auto text-center text-md-left mb-2 mb-md-0'>")
                    .Append("Published on: ").Append(formattedDate)
                    .Append("</div>");
            }
            if (item.Links.Any())
            {
                html.Append("<div class='col-12 col-md-auto text-center text-md-right'>")
                    .Append("<a href='").Append(item.Links.First().Uri.ToString()).Append("' class='btn btn-primary mt-2 mt-md-0'>Read more</a>")
                    .Append("</div>");
            }
            html.Append("</div>")
                .Append("</div></div></div>");
        }
        html.Append("</div>");
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
    htmlBuilder.Append("<div class='container-fluid mt-5' style='padding: 0 15px;'>");

    if (syndicationFeed.Title != null)
    {
        htmlBuilder.Append("<div class='row mb-4 justify-content-center'>") 
                   .Append("<div class='col-12 col-md-10 col-lg-8'>") 
                   .Append("<h1 class='display-4 text-center' style='font-size: 2.5rem;'>").Append(syndicationFeed.Title.Text).Append("</h1>")
                   .Append("</div>")
                   .Append("</div>");
    }

    foreach (var item in feedItems)
    {
        bool isRtlContent = IsRtlContent(item.Summary.Text); 
        var cardClass = isRtlContent ? "card rtl" : "card";
        htmlBuilder.Append($"<div class='row mb-4 justify-content-center'>")
                   .Append($"<div class='col-12 col-md-10 col-lg-8'>")
                   .Append($"<div class='{cardClass}' style='word-wrap: break-word;'>");

        if (item.Title != null)
        {
            htmlBuilder.Append("<div class='card-header'>")
                       .Append("<h5 class='card-title font-weight-bold text-center' style='font-size: 1.25rem;'>").Append(item.Title.Text).Append("</h5>")
                       .Append("</div>");
        }

        htmlBuilder.Append("<div class='card-body'>");
        var description = item.Summary?.Text ?? string.Empty;
        description = Regex.Replace(description, "<iframe(.+?)</iframe>", "<div class='video-container'><iframe$1</iframe></div>", RegexOptions.IgnoreCase | RegexOptions.Singleline);
        description = description.Replace("<img ", "<img style='max-width:100%;height:auto;' ");

        htmlBuilder.Append("<p class='card-text'>").Append(description).Append("</p>");
        htmlBuilder.Append("</div>");
        htmlBuilder.Append("<div class='card-footer text-muted d-flex flex-wrap justify-content-between align-items-center'>");


        if (item.PublishDate != null)
        {
            string formattedDate;
            try
            {
                var publishDate = item.PublishDate.ToLocalTime(); 
                formattedDate = publishDate.ToString("f"); 
            }
            catch (ArgumentOutOfRangeException)
            {
                formattedDate = "Unknown"; 
            }
            htmlBuilder.Append("<div class='col-12 col-md-auto text-center text-md-left mb-2 mb-md-0'>")
                       .Append("Published on: ").Append(formattedDate)
                       .Append("</div>");
        }

        if (item.Links.Any())
        {
            htmlBuilder.Append("<div class='col-12 col-md-auto text-center text-md-right'>")
                       .Append("<a href='").Append(item.Links.First().Uri.ToString()).Append("' class='btn btn-primary mt-2 mt-md-0'>Read more</a>")
                       .Append("</div>");
        }

        htmlBuilder.Append("</div>")
                   .Append("</div></div></div>");
    }

    htmlBuilder.Append("</div>");

    return Results.Content(htmlBuilder.ToString(), "text/html");
});

app.MapGet("/feeds-urls", async (HttpContext context, IDbConnection dbConnection) =>
{
    var userId = context.Session.GetString("UserId");
    if (userId == null || !context.User.Identity.IsAuthenticated)
    {
        return Results.BadRequest("User not logged in");
    }
    var feeds = await dbConnection.QueryAsync<Feed>("SELECT Url FROM Feeds WHERE UserId = @UserId", new { UserId = userId });
    var tokens = antiforgery.GetAndStoreTokens(context);

    var htmlBuilder = new StringBuilder();
    htmlBuilder.Append("<ul class='list-group' id='feed-list'>");
    htmlBuilder.AppendFormat(@"
    <li class='list-group-item d-flex justify-content-between align-items-center feed-url'>
        <span class='feed-url-text text-truncate'>All Feeds</span>
        <div class='btn-group'>
            <button type='button' class='btn btn-primary btn-sm view-btn' hx-get='/feeds' hx-target='#feeds' hx-swap='innerHTML   hx-trigger='every 1m''>View</button>
        </div>
    </li>", tokens.RequestToken);

    foreach (var feed in feeds)
    {
        htmlBuilder.AppendFormat(@"
        <li class='list-group-item d-flex justify-content-between align-items-center feed-url' data-url='{0}'>
            <span class='feed-url-text text-truncate' style='flex: 1;'>{0}</span>
            <div class='btn-group' role='group'>
                <button type='button' class='btn btn-primary btn-sm view-btn' hx-get='/getFeedData?url={0}' hx-target='#feeds' hx-swap='innerHTML   hx-trigger='every 1m''>View</button>

                <form hx-delete='/feeds' hx-confirm='Are you sure you want to delete this feed?' hx-vals='{{""Url"":""{0}""}}' hx-target='closest li' hx-swap='outerHTML' class='d-inline'>
                    <input type='hidden' name='__RequestVerificationToken' value='{1}' />
                    <button type='submit' class='btn btn-danger btn-sm delete-btn'>Delete</button>
                </form>
            </div>
        </li>", feed.Url, tokens.RequestToken);
    }
    htmlBuilder.Append("</ul>");

    return Results.Text(htmlBuilder.ToString(), "text/html");
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
    return Results.Ok();
});

app.MapPost("/generate-share-link", async (HttpContext context, IDbConnection connection) =>
{
    var userEmail = context.User.Identity.Name;
    if (string.IsNullOrEmpty(userEmail))
        return Results.Unauthorized();

    using (var dbConnection = new SqliteConnection("Data Source=./wwwroot/RssReader.db"))
    {
        var user = await dbConnection.QueryFirstOrDefaultAsync<User>("SELECT * FROM Users WHERE Email = @Email", new { Email = userEmail });
        if (user == null) return Results.NotFound("User not found");

        // Generate a unique token
        var shareToken = Guid.NewGuid().ToString();

        // Set an expiration date for the link (e.g., 7 days from now)
        var expirationDate = DateTime.UtcNow.AddDays(7);

        // Save the shared link data in the database
        await dbConnection.ExecuteAsync("INSERT INTO SharedLinks (UserId, Token, ExpirationDate) VALUES (@UserId, @Token, @ExpirationDate)",
            new { UserId = user.id, Token = shareToken, ExpirationDate = expirationDate });

        var shareLink = $"{context.Request.Scheme}://{context.Request.Host}/shared-feeds/{shareToken}";
        return Results.Content(shareLink, "text/plain");
    }
});

app.MapGet("/shared-feeds/{token}", async (HttpContext context, IDbConnection dbConnection, string token) =>
{
    var sharedLink = await dbConnection.QueryFirstOrDefaultAsync<SharedLink>(
        "SELECT * FROM SharedLinks WHERE Token = @Token AND ExpirationDate > @Now",
        new { Token = token, Now = DateTime.UtcNow });

    if (sharedLink == null) return Results.NotFound("Shared feeds not found or link has expired");

    var feeds = await dbConnection.QueryAsync<Feed>(
        "SELECT * FROM Feeds WHERE UserId = @UserId",
        new { UserId = sharedLink.UserId });

    var feedItems = new List<SyndicationItem>();
    foreach (var feed in feeds)
    {
        using var reader = XmlReader.Create(feed.Url);
        var syndicationFeed = SyndicationFeed.Load(reader);
        feedItems.AddRange(syndicationFeed.Items);
    }
    feedItems = feedItems.OrderByDescending(item => item.PublishDate).ToList();

    var html = new StringBuilder();
    html.Append("<!DOCTYPE html>")
        .Append("<html lang='en'>")
        .Append("<head>")
        .Append("<meta charset='UTF-8'>")
        .Append("<meta name='viewport' content='width=device-width, initial-scale=1.0'>")
        .Append("<title>Shared Feeds</title>")
        .Append("<link href='https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css' rel='stylesheet'>")
         .Append("<style>")
        .Append(".card { flex: 1 0 100%; max-width: 100%; }")
        .Append(".rtl { direction: rtl; text-align: right; }")
        .Append(".video-container { position: relative; padding-bottom: 56.25%; height: 0; overflow: hidden; }")
        .Append(".video-container iframe { position: absolute; top: 0; left: 0; width: 100%; height: 100%; }")
        .Append(".feed-url-text { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }")
        .Append("</style>")
        .Append("</head>")
        .Append("<body>")
        .Append("<div class='container-fluid mt-5' style='padding: 0 15px;'>");

    html.Append("<div class='row mb-4 justify-content-center'>")
        .Append("<div class='col-12 col-md-10 col-lg-8'>")
        .Append("<h1 class='display-4 text-center' style='font-size: 2.5rem;'>Shared Feeds</h1>")
        .Append("</div>")
        .Append("</div>");

    foreach (var item in feedItems)
    {
        bool isRtlContent = IsRtlContent(item.Summary.Text); 
        var cardClass = isRtlContent ? "card rtl" : "card";

        html.Append("<div class='row mb-4 justify-content-center'>")
           .Append("<div class='col-12 col-md-10 col-lg-8'>")
           .Append($"<div class='{cardClass}' style='word-wrap: break-word;'>");

        if (item.Title != null)
        {
            html.Append("<div class='card-header'>")
                .Append("<h5 class='card-title font-weight-bold text-center' style='font-size: 1.25rem;'>").Append(item.Title.Text).Append("</h5>")
                .Append("</div>");
        }

        html.Append("<div class='card-body'>");

        var description = item.Summary?.Text ?? string.Empty;
        description = Regex.Replace(description, "<iframe(.+?)</iframe>", "<div class='video-container'><iframe$1</iframe></div>", RegexOptions.IgnoreCase | RegexOptions.Singleline);
        description = description.Replace("<img ", "<img style='max-width:100%;height:auto;' ");

        html.Append("<p class='card-text'>").Append(description).Append("</p>");
        html.Append("</div>");
        html.Append("<div class='card-footer text-muted d-flex flex-wrap justify-content-between align-items-center'>");

        if (item.PublishDate != null)
        {
            string formattedDate;
            try
            {
                var publishDate = item.PublishDate.ToLocalTime(); 
                formattedDate = publishDate.ToString("f"); 
            }
            catch (ArgumentOutOfRangeException)
            {
                formattedDate = "Unknown"; 
            }

            html.Append("<div class='col-12 col-md-auto text-center text-md-left mb-2 mb-md-0'>")
                .Append("Published on: ").Append(formattedDate)
                .Append("</div>");
        }

        if (item.Links.Any())
        {
            html.Append("<div class='col-12 col-md-auto text-center text-md-right'>")
                .Append("<a href='").Append(item.Links.First().Uri.ToString()).Append("' class='btn btn-primary mt-2 mt-md-0'>Read more</a>")
                .Append("</div>");
        }

        html.Append("</div>")
            .Append("</div></div></div>");
    }

    html.Append("</div>")
        .Append("<script src='https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js'></script>")
        .Append("<script src='https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.16.0/umd/popper.min.js'></script>")
        .Append("<script src='https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js'></script>")
        .Append("</body>")
        .Append("</html>");

    return Results.Content(html.ToString(), "text/html");
});
#endregion

app.Run();

