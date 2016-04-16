using System;
using System.Threading;
using System.Threading.Tasks;

using frɪdʒ.Db;
using frɪdʒ.http;
using frɪdʒ.http.handlers;
using frɪdʒ.ws;

namespace frɪdʒ
{
	internal static class Program
	{
		private static void Main()
		{
			AppDomain.CurrentDomain.UnhandledException += (sender, args) => Console.Error.WriteLine(args.ExceptionObject);

			ThreadPool.SetMinThreads(HttpServerSettings.Concurrency, HttpServerSettings.Concurrency);
			ThreadPool.SetMaxThreads(HttpServerSettings.Concurrency, HttpServerSettings.Concurrency);

			var cancellation = new CancellationTokenSource();
			var token = cancellation.Token;

			var wsServer = new WsServer<User>(9999, ws => Users.Find(ws.HttpRequest.Cookies?.GetAuth()));

			var authHandler = new AuthHandler(login => Task.Run(() => wsServer.BroadcastAsync(user => AuthHandler.FormatUserMessage(user, login), token), token));
			var foodHandler = new FoodHandler((login, food) => Task.Run(() => wsServer.BroadcastAsync(user => FoodHandler.FormatUserMessage(user, login, food), token), token));

			var staticHandler = new StaticHandler("static", ctx =>
			{
				var url = ctx.Request.Url;
				if(url.HostNameType != UriHostNameType.Dns && url.HostNameType != UriHostNameType.IPv4 && url.HostNameType == UriHostNameType.IPv6)
					throw new HttpException(400, "Invalid host");

				ctx.Response.Headers["X-Frame-Options"] = "deny";
				ctx.Response.Headers["X-XSS-Protection"] = "1; mode=block";
				ctx.Response.Headers["Content-Security-Policy"] = $"default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self' ws://{url.Host}:9999;";

				ctx.SetCsrfTokenCookie();
			});

			var httpServer = new HttpServer(8888)
				.AddHandler("POST", "/signin", authHandler.SignInAsync)
				.AddHandler("POST", "/signup", authHandler.SignUpAsync)
				.AddHandler("POST", "/put", foodHandler.PutAsync)
				.AddHandler("GET", "/get", foodHandler.GetAsync)
				.AddHandler("GET", "/", staticHandler.GetAsync);

			Console.CancelKeyPress += (sender, args) =>
			{
				Console.Error.WriteLine("Stopping...");
				args.Cancel = true;
				cancellation.Cancel();
			};

			Task.WaitAll(wsServer.AcceptLoopAsync(token), httpServer.AcceptLoopAsync(token));
		}
	}
}