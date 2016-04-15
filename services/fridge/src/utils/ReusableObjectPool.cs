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
			items = new ConcurrentStack<T>(Enumerable.Range(0, size).Select(i => factory()));
			semaphore = new SemaphoreSlim(size, size);
		}

		public async Task<PooledObject> AcquireAsync()
		{
			T item;
			await semaphore.WaitAsync().ConfigureAwait(false);
			if(items.TryPop(out item))
				return new PooledObject(item, this);
			throw new InvalidOperationException("Pool is empty");
		}

		private void Release(PooledObject obj)
		{
			items.Push(obj.Item);
			semaphore.Release();
		}

		internal struct PooledObject : IDisposable
		{
			public PooledObject(T item, ReusableObjectPool<T> pool)
			{
				sync = 0;
				Item = item;
				this.pool = pool;
			}

			public void Dispose()
			{
				if(Interlocked.CompareExchange(ref sync, 1, 0) == 0)
					pool.Release(this);
			}

			public readonly T Item;

			private readonly ReusableObjectPool<T> pool;
			private int sync;
		}

		private readonly ConcurrentStack<T> items;
		private readonly SemaphoreSlim semaphore;
	}
}