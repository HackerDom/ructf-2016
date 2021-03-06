﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

using frɪdʒ.utils;

namespace frɪdʒ.http
{
	public static class RequestAsyncHelper
	{
		static RequestAsyncHelper()
		{
			RequestBuffersPool = new ReusableObjectPool<byte[]>(() => new byte[HttpServerSettings.MaxRequestSize], HttpServerSettings.Concurrency);
		}

		public static async Task<string> ReadStringAsync(this HttpListenerContext context)
		{
			if(!context.Request.HasEntityBody || context.Request.ContentLength64 == 0)
				return null;
			//NOTE: Mono breaks keep-alive connection on disponsing HttpRequestStream
			//using(var stream = request.InputStream)
			try
			{
				//NOTE: Vulnerability #1 part #0: Static pool of request buffers
				using(var buffer = await RequestBuffersPool.AcquireAsync())
				{
					try
					{
						await
							context.Request.InputStream.ReadToBufferAsync(buffer.Item)
								.WithTimeout(HttpServerSettings.ReadWriteTimeout) //NOTE: HttpRequestStream is not cancellable with CancellationToken :(
								.ConfigureAwait(false);
					}
					catch(Exception e)
					{
						context.Close(408);
						throw new HttpConnectionClosed(e);
					}
					//NOTE: Vulnerability #1 part #1: Do NOT rely on Content-Length field!
					return Encoding.UTF8.GetString(buffer.Item, 0, (int)context.Request.ContentLength64);
				}
			}
			finally
			{
				context.Request.InputStream.Close();
			}
		}

		public static async Task<Dictionary<string, string>> ReadPostDataAsync(this HttpListenerContext context)
		{
			var data = await context.ReadStringAsync().ConfigureAwait(false);
			return string.IsNullOrEmpty(data) ? null : data.Split('&').Select(pair => pair.Split('=')).Where(pair => pair.Length == 2).ToDict(pair => WebUtility.UrlDecode(pair[0]), pair => WebUtility.UrlDecode(pair[1]));
		}

		private static readonly ReusableObjectPool<byte[]> RequestBuffersPool;
	}
}