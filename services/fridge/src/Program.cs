using System;
using System.Threading;
using System.Threading.Tasks;

using frɪdʒ.http;
using frɪdʒ.ws;

namespace frɪdʒ
{
	internal static class Program
	{
		private static void Main()
		{
			ThreadPool.SetMinThreads(HttpServerSettings.Concurrency, HttpServerSettings.Concurrency);
			ThreadPool.SetMaxThreads(HttpServerSettings.Concurrency, HttpServerSettings.Concurrency);

			var cancellation = new CancellationTokenSource();
			var token = cancellation.Token;

			var wsServer = new WsServer(9999);
			var foodHandler = new FoodHandler((id, msg) => Task.Run(() => wsServer.BroadcastAsync($"{id}:{msg}", token), token));

			var wsServerTask = wsServer.AcceptLoopAsync(token);

			var httpServerTask = new HttpServer(8888)
				.AddHandler("POST", "/put", foodHandler.ProcessPutRequestAsync)
				.AddHandler("GET", "/get", foodHandler.ProcessGetRequestAsync)
				.AddHandler("GET", "/", new StaticHandler("static").ProcessRequestAsync)
				.AcceptLoopAsync(token);

			Console.CancelKeyPress += (sender, args) =>
			{
				Console.WriteLine("Stopping...");
				args.Cancel = true;
				cancellation.Cancel();
			};

			Task.WaitAll(httpServerTask, wsServerTask);
		}
	}
}