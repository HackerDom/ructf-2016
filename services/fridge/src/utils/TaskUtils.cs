using System;
using System.Threading;
using System.Threading.Tasks;

namespace frɪdʒ.utils
{
	internal static class TaskUtils
	{
		public static Task<T> WithTimeout<T>(this Task<T> task, int timeout)
		{
			if(task.IsCompleted || timeout == Timeout.Infinite)
				return task;

			var source = new TaskCompletionSource<T>();

			if(timeout == 0)
			{
				source.SetException(new TimeoutException());
				return source.Task;
			}

			var timer = new Timer(state => ((TaskCompletionSource<T>)state).TrySetException(new TimeoutException()), source, timeout, Timeout.Infinite);

			task.ContinueWith(t =>
			{
				timer.Dispose();
				switch(task.Status)
				{
					case TaskStatus.Faulted:
						source.TrySetException(task.Exception);
						break;
					case TaskStatus.Canceled:
						source.TrySetCanceled();
						break;
					case TaskStatus.RanToCompletion:
						source.TrySetResult(task.Result);
						break;
				}
			}, TaskContinuationOptions.ExecuteSynchronously);

			return source.Task;
		}
	}
}