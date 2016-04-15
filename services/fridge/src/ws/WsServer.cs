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
	internal class WsServer<T>
	{
		public WsServer(int port, Func<WebSocket, T> auth)
		{
			this.auth = auth;
			var timeout = TimeSpan.FromSeconds(3);
			var readWriteTimeout = TimeSpan.FromSeconds(1);
			var options = new WebSocketListenerOptions
			{
				UseNagleAlgorithm = false,
				PingMode = PingModes.BandwidthSaving,
				PingTimeout = timeout,
				NegotiationTimeout = timeout,
				WebSocketSendTimeout = readWriteTimeout,
				WebSocketReceiveTimeout = readWriteTimeout,
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
					//Console.WriteLine($"[{ws.RemoteEndpoint}] WS connected v{ws.HttpRequest.WebSocketVersion} as '{ws.HttpRequest.Headers["User-Agent"]}' from '{ws.HttpRequest.Headers["Origin"]}'");
#pragma warning disable CS4014 // Because this call is not awaited, execution of the current method continues before the call is completed
					Task.Run(async () =>
					{
						await Task.Delay(100, token); //NOTE: ws4py issue workaround =\
						await TrySendHelloAsync(ws, token);
						sockets[ws] = new State {Item = auth(ws), Lock = new AsyncLockSource()};
					}, token);
#pragma warning restore CS4014 // Because this call is not awaited, execution of the current method continues before the call is completed
				} catch {}
			}
		}

		public Task BroadcastAsync(Func<T, string> format, CancellationToken token)
		{
			return
				Task.WhenAll(
					sockets
						.Where(pair =>
						{
							var ws = pair.Key;
							if(ws.IsConnected)
								return true;
							Remove(ws);
							return false;
						})
						.Select(pair => TrySendAsync(pair.Key, pair.Value, format, token)));
		}

		private async Task TrySendHelloAsync(WebSocket ws, CancellationToken token)
		{
			try
			{
				await ws.WriteStringAsync(HelloMessage, token).ConfigureAwait(false);
				//Console.WriteLine($"[{ws.RemoteEndpoint}] WS sent '{HelloMessage}'");
			}
			catch
			{
				ws.Dispose();
				//Console.WriteLine($"[{ws.RemoteEndpoint}] WS closed");
			}
		}

		private async Task TrySendAsync(WebSocket ws, State state, Func<T, string> format, CancellationToken token)
		{
			try
			{
				using(await state.Lock.AcquireAsync(token))
					await ws.WriteStringAsync(format.TryOrDefault(state.Item), token).ConfigureAwait(false);
				//Console.WriteLine($"[{ws.RemoteEndpoint}] WS sent '{msg}'");
			}
			catch
			{
				Remove(ws);
			}
		}

		private void Remove(WebSocket ws)
		{
			State state;
			if(sockets.TryRemove(ws, out state))
			{
				state.Lock.Dispose();
				ws.Dispose();
				//Console.WriteLine($"[{ws.RemoteEndpoint}] WS closed");
			}
		}

		private struct State
		{
			public T Item;
			public AsyncLockSource Lock;
		}

		private const string HelloMessage = "hello";
		private readonly ConcurrentDictionary<WebSocket, State> sockets = new ConcurrentDictionary<WebSocket, State>();
		private readonly WebSocketListener listener;
		private readonly Func<WebSocket, T> auth;
		private readonly IPEndPoint endpoint;
	}
}