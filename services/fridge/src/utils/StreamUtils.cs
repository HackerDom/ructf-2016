using System.IO;
using System.Threading.Tasks;

namespace frɪdʒ.utils
{
	internal static class StreamUtils
	{
		public static async Task<int> ReadToBufferAsync(this Stream source, byte[] buffer)
		{
			int bytesRead, total = 0;
			while((bytesRead = await source.ReadAsync(buffer, total, buffer.Length - total).ConfigureAwait(false)) > 0)
				total += bytesRead;
			return total;
		}
	}
}