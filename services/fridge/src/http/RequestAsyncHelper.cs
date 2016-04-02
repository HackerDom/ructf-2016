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

		public static async Task<string> ReadStringAsync(this HttpListenerRequest request)
		{
			if(!request.HasEntityBody || request.ContentLength64 == 0)
				return null;
			//NOTE: Mono breaks keep-alive connection on disponsing HttpRequestStream
			//using(var stream = request.InputStream)
			try
			{
				//NOTE: Vulnerability #1 part #0: Static pool of request buffers
				using(var buffer = await RequestBuffersPool.AcquireAsync())
				{
					await request.InputStream.ReadToBufferAsync(buffer.Item);
					//NOTE: Vulnerability #1 part #1: Do NOT rely on Content-Length field!
					return Encoding.UTF8.GetString(buffer.Item, 0, (int)request.ContentLength64);
				}
			}
			finally
			{
				request.InputStream.Close();
			}
		}

		private static readonly ReusableObjectPool<byte[]> RequestBuffersPool;
	}
}