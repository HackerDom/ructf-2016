using System.Threading;

using frɪdʒ.http;

namespace frɪdʒ
{
	internal static class Program
	{
		private static void Main()
		{
			ThreadPool.SetMinThreads(HttpServerSettings.Concurrency, HttpServerSettings.Concurrency);
			ThreadPool.SetMaxThreads(HttpServerSettings.Concurrency, HttpServerSettings.Concurrency);

			new HttpServer(8888)
				.AddHandler("POST", "/put", FoodHandler.ProcessPutRequestAsync)
				.AddHandler("GET", "/get", FoodHandler.ProcessGetRequestAsync)
				.AddHandler("GET", "/", new StaticHandler("static").ProcessRequestAsync)
				.Loop().Wait();
		}
	}
}