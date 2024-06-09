using Microsoft.AspNetCore.Builder;
using Microsoft.Data.Sqlite;
using Dapper;
using System.Data;
using RssReader.Models;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

string DbPath = "Data Source=./wwwroot/RssReader.db";
await using var connection = new SqliteConnection(DbPath);

app.MapPost("/signup", async (UserInput userInput) =>
{
    string id = Guid.NewGuid().ToString();
    await connection.ExecuteAsync("INSERT INTO Users (id,email, password) VALUES (@id,@email, @password)", new {id=id, email = userInput.email, password = userInput.password });
    return Results.Created();
});

app.MapPost("/login", async (UserInput userInput) =>
{
    var user = await connection.QueryFirstOrDefaultAsync<User>("SELECT * FROM Users WHERE email = @email AND password = @password", new { email = userInput.email, password = userInput.password });
    if (user == null) return Results.NotFound();
    return Results.Ok(user);
});

app.MapPost("/feeds", async ([FromBody]  Feed feed) =>
{
    var user = await connection.QueryFirstOrDefaultAsync<User>("SELECT * FROM Users WHERE Id = @UserId", new { UserId = feed.UserId });
    if (user == null) return Results.NotFound("User not found");
    await connection.ExecuteAsync("INSERT INTO Feeds (Url, UserId) VALUES (@Url, @UserId)", new { Url = feed.Url, UserId = feed.UserId });
    return Results.Created($"/feeds/{feed.Url}", feed);
});

app.MapGet("/users/{userId}/feeds", async (string userId) =>
{
    var feeds = await connection.QueryAsync<Feed>("SELECT * FROM Feeds WHERE UserId = @UserId", new { UserId = userId });
    return Results.Ok(feeds);
});

app.MapDelete("/feeds", async ([FromBody] Feed feed) =>
{
    var user = await connection.QueryFirstOrDefaultAsync<User>("SELECT * FROM Users WHERE Id = @UserId", new { UserId = feed.UserId });
    if (user == null) return Results.NotFound("User not found");
    await connection.ExecuteAsync("DELETE FROM Feeds WHERE Url = @Url AND UserId = @UserId", new { Url = feed.Url, UserId = feed.UserId });
    return Results.Ok();
});

app.Run();
