using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace frɪdʒ.utils
{
	internal class ReusableObjectPool<T>
	{
		public ReusableObjectPool(Func<T> factory, int size)
		{
			items = new ConcurrentBag<PooledObject<T>>(Enumerable.Range(0, size).Select(i => new PooledObject<T>(this, factory())));
			semaphore = new SemaphoreSlim(size, size);
		}

		public async Task<PooledObject<T>> AcquireAsync()
		{
			PooledObject<T> item;
			await semaphore.WaitAsync();
			return items.TryTake(out item) ? item : null;
		}

		public void Release(PooledObject<T> item)
		{
			items.Add(item);
			semaphore.Release();
		}

		private static ConcurrentBag<PooledObject<T>> items;
		private static SemaphoreSlim semaphore;
	}

	internal class PooledObject<T> : IDisposable
	{
		public PooledObject(ReusableObjectPool<T> pool, T item)
		{
			this.pool = pool;
			Item = item;
		}

		public void Dispose()
		{
			pool.Release(this);
		}

		public readonly T Item;

		private readonly ReusableObjectPool<T> pool;
	}
}