using System;
using System.Threading;
using System.Threading.Tasks;

namespace frɪdʒ.utils
{
	internal class AsyncLockSource : IDisposable
	{
		public async Task<AsyncLock> AcquireAsync(CancellationToken token)
		{
			await semaphore.WaitAsync(token).ConfigureAwait(false);
			return new AsyncLock(this);
		}

		public void Dispose()
		{
			semaphore.Dispose();
		}

		private void Release()
		{
			semaphore.Release();
		}

		internal struct AsyncLock : IDisposable
		{
			public AsyncLock(AsyncLockSource source)
			{
				this.source = source;
			}

			public void Dispose()
			{
				source.Release();
			}

			private readonly AsyncLockSource source;
		}

		private readonly SemaphoreSlim semaphore = new SemaphoreSlim(1, 1);
	}
}