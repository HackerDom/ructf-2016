using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace frɪdʒ.http
{
	internal class HttpServer
	{
		public HttpServer(int port)
		{
			listener = new HttpListener {IgnoreWriteExceptions = true};
			listener.Prefixes.Add($"http://*:{port}/");
		}

		public HttpServer AddHandler(string method, string path, Func<HttpListenerContext, Task> callback)
		{
			if(listener.IsListening)
				throw new InvalidOperationException("Can't add handler after listening started");
			handlers.Add(new Handler {Path = path.TrimEnd('/'), Method = method, Callback = callback});
			return this;
		}

		public async Task AcceptLoopAsync(CancellationToken token)
		{
			token.Register(() =>
			{
				listener.Stop();
				Console.Error.WriteLine("HttpServer stopped");
			});

			listener.Start();
			Console.Error.WriteLine($"HttpServer started at '{string.Join(";", listener.Prefixes)}'");
			while(!token.IsCancellationRequested)
			{
				try
				{
					var context = await listener.GetContextAsync().ConfigureAwait(false);
					//Console.WriteLine($"[{context.Request.RemoteEndPoint}] {context.Request.HttpMethod} {context.Request.Url.PathAndQuery}");
#pragma warning disable CS4014 // Because this call is not awaited, execution of the current method continues before the call is completed
					Task.Run(() => TryProcessRequestAsync(context), token);
#pragma warning restore CS4014 // Because this call is not awaited, execution of the current method continues before the call is completed
				}
				catch(Exception e)
				{
					if(!token.IsCancellationRequested)
						Console.Error.WriteLine(e);
				}
			}
		}

		private async void TryProcessRequestAsync(HttpListenerContext context)
		{
			try
			{
				var response = context.Response;
				response.Headers["Server"] = HttpServerSettings.ServerName;
				//NOTE: Mono breaks keep-alive connection on disponsing HttpResponse
				//using(var response = context.Response)
				try
				{
					await ProcessRequestAsync(context).ConfigureAwait(false);
				}
				catch(HttpConnectionClosed) {}
				catch(Exception e)
				{
					//Console.Error.WriteLine(e);
					var httpException = e as HttpException;
					response.StatusCode = httpException?.Status ?? 500;
					response.ContentType = "text/plain; charset=utf-8";
					await context.WriteStringAsync(httpException?.Message ?? "Internal Server Error");
				}
				finally
				{
					response.Close();
				}
			}
			catch(Exception e)
			{
				if(!(e is InvalidOperationException))
					Console.Error.WriteLine(e);
			}
		}

		private async Task ProcessRequestAsync(HttpListenerContext context)
		{
			var handler = FindHandler(context.Request.Url.LocalPath);
			if(handler == null)
				throw new HttpException(404, "Not Found");

			if(context.Request.HttpMethod != handler.Method)
				throw new HttpException(405, "Method Not Allowed");

			if(context.Request.HasEntityBody)
			{
				if(context.Request.ContentLength64 < 0)
					throw new HttpException(411, "Length Required");

				if(context.Request.ContentLength64 > HttpServerSettings.MaxRequestSize)
					throw new HttpException(413, "Request Entity Too Large");
			}

			await handler.Callback(context).ConfigureAwait(false);
		}

		private Handler FindHandler(string path)
		{
			return handlers.Find(record => path.StartsWith(record.Path, StringComparison.Ordinal) && (path.Length == record.Path.Length || path[record.Path.Length] == '/'));
		}

		private class Handler
		{
			public string Path;
			public string Method;
			public Func<HttpListenerContext, Task> Callback;
		}

		private readonly List<Handler> handlers = new List<Handler>();
		private readonly HttpListener listener;
	}

	public class HttpException : Exception
	{
		public HttpException(int status, string message)
			: base(message)
		{
			Status = status;
		}

		public int Status { get; }
	}

	public class HttpConnectionClosed : Exception
	{
		public HttpConnectionClosed(Exception innerException)
			: base(null, innerException)
		{
		}
	}
}