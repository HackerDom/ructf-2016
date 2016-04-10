using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

using frɪdʒ.utils;

using vtortola.WebSockets;
using vtortola.WebSockets.Rfc6455;

namespace frɪdʒ.ws
{
	internal class WsServer
	{
		public WsServer(int port)
		{
			var timeout = TimeSpan.FromSeconds(5);
			var options = new WebSocketListenerOptions
			{
				UseNagleAlgorithm = false,
				PingTimeout = timeout,
				NegotiationTimeout = timeout,
				WebSocketSendTimeout = timeout,
				WebSocketReceiveTimeout = timeout,
				SubProtocols = new[] {"text"}
			};

			endpoint = new IPEndPoint(IPAddress.Any, port);
			listener = new WebSocketListener(endpoint, options);
			listener.Standards.RegisterStandard(new WebSocketFactoryRfc6455(listener));
		}

		public async Task AcceptLoopAsync(CancellationToken token)
		{
			token.Register(() =>
			{
				listener.Dispose();
				Console.Error.WriteLine("WebSocketServer stopped");
			});

			listener.Start();
			Console.Error.WriteLine($"WebSocketServer started at '{endpoint}'");
			while(!token.IsCancellationRequested)
			{
				try
				{
					var ws = await listener.AcceptWebSocketAsync(token).ConfigureAwait(false);
					if(ws == null)
						continue;
					//Console.WriteLine($"[{ws.RemoteEndpoint}] WS v{ws.HttpRequest.Headers.WebSocketVersion}");
#pragma warning disable CS4014 // Because this call is not awaited, execution of the current method continues before the call is completed
					Task.Run(async () =>
					{
						await TrySendAsync(ws, "hello", token);
						sockets[ws] = 0;
					}, token);
#pragma warning restore CS4014 // Because this call is not awaited, execution of the current method continues before the call is completed
				} catch {}
			}
		}

		public Task BroadcastAsync(string msg, CancellationToken token)
		{
			return
				Task.WhenAll(
					sockets.EnumerateKeys()
						.Where(ws =>
						{
							if(ws.IsConnected)
								return true;
							if(sockets.TryRemove(ws))
								ws.Dispose();
							return false;
						})
						.Select(ws => TrySendAsync(ws, msg, token)));
		}

		private static async Task TrySendAsync(WebSocket ws, string msg, CancellationToken token)
		{
			try
			{
				await ws.WriteStringAsync(msg, token).ConfigureAwait(false);
			}
			catch
			{
				ws.Dispose();
			}
		}

		private readonly ConcurrentDictionary<WebSocket, int> sockets = new ConcurrentDictionary<WebSocket, int>();
		private readonly WebSocketListener listener;
		private readonly IPEndPoint endpoint;
	}
}