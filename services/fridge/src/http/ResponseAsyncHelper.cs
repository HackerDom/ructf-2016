using System.Net;
using System.Text;
using System.Threading.Tasks;

using frɪdʒ.utils;

namespace frɪdʒ.http
{
	public static class ResponseAsyncHelper
	{
		static ResponseAsyncHelper()
		{
			ResponseBuffersPool = new ReusableObjectPool<byte[]>(() => new byte[HttpServerSettings.MaxResponseSize], HttpServerSettings.Concurrency);
		}

		public static async Task WriteDataAsync(this HttpListenerResponse response, byte[] data)
		{
			await response.WriteDataAsync(data, 0, data?.Length ?? 0);
		}

		public static async Task WriteDataAsync(this HttpListenerResponse response, byte[] data, int offset, int count)
		{
			if(data == null || count == 0)
				response.ContentLength64 = 0;
			else
			{
				response.ContentLength64 = count;
				await response.OutputStream.WriteAsync(data, offset, count);
			}
		}

		public static async Task WriteStringAsync(this HttpListenerResponse response, string value, Encoding encoding = null)
		{
			using(var buffer = await ResponseBuffersPool.AcquireAsync())
			{
				/* NOTE: In theory here we need to check that there is enough space in buffer to store encoded string. Something like that: encoding.GetMaxByteCount(value.Length) <= buffer.Length
				 * If not - use Encoder.Convert to encode string by chunks. Omit this stuff for simplicity :) */
				var length = (encoding ?? Encoding.UTF8).GetBytes(value, 0, value.Length, buffer.Item, 0);
				await response.WriteDataAsync(buffer.Item, 0, length);
			}
		}

		private static readonly ReusableObjectPool<byte[]> ResponseBuffersPool;
	}
}