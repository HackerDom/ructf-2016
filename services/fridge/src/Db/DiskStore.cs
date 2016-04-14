using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using frɪdʒ.utils;

namespace frɪdʒ.Db
{
	internal class DiskStore
	{
		public DiskStore(string filename, Action<byte[]> add)
		{
			var filepath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, filename);
			Directory.CreateDirectory(Path.GetDirectoryName(filepath));
			TryLoad(filepath, add);
			writer = new StreamWriter(filepath, true, Encoding.ASCII, BufferSize);
			Task.Factory.StartNew(FlushLoopAsync, TaskCreationOptions.LongRunning);
		}

		public async Task WriteAsync(byte[] data)
		{
			var line = Convert.ToBase64String(data);
			using(await asyncLock.AcquireAsync(CancellationToken.None))
			{
				await writer.WriteLineAsync();
				await writer.WriteLineAsync(line);
			}
		}

		private static void TryLoad(string filepath, Action<byte[]> load)
		{
			try
			{
				File.ReadLines(filepath)
					.Where(line => line != string.Empty)
					.Select(TryConvert)
					.Where(data => data != null)
					.ForEach(load);
			}
			catch(FileNotFoundException) { }
		}

		private async Task FlushLoopAsync()
		{
			while(true)
			{
				await Task.Delay(FlushPeriod);
				using(await asyncLock.AcquireAsync(CancellationToken.None))
					await writer.FlushAsync();
			}
		}

		private static byte[] TryConvert(string line)
		{
			try
			{
				return Convert.FromBase64String(line);
			}
			catch(FormatException)
			{
				return null;
			}
		}

		private const int FlushPeriod = 3000;
		private const int BufferSize = 256 * 1024;
		private readonly AsyncLockSource asyncLock = new AsyncLockSource();
		private readonly StreamWriter writer;
	}
}