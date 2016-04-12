using System;
using System.Collections.Concurrent;
using System.Net;
using System.Threading.Tasks;

using frɪdʒ.utils;

namespace frɪdʒ.http
{
	internal class FoodHandler
	{
		public FoodHandler(Action<Guid, string> callback)
		{
			this.callback = callback;
		}

		public async Task ProcessPutRequestAsync(HttpListenerContext context)
		{
			var data = await context.ReadStringAsync();
			if(data == null)
				return;

			var id = Guid.NewGuid();
			Db[id] = data;

			var result = id.ToString("N") + ":" + string.Join(",", data.FindAll(TestPatterns));
			await context.WriteStringAsync(result);

			callback(id, data);
		}

		public async Task ProcessGetRequestAsync(HttpListenerContext context)
		{
			Guid id;
			string data;
			if(!(Guid.TryParse(context.Request.QueryString["id"], out id) && (data = Db.GetOrDefault(id)) != null))
				throw new HttpException(404, "Food not found");

			await context.WriteStringAsync(data);
		}

		private static readonly ConcurrentDictionary<Guid, string> Db = new ConcurrentDictionary<Guid, string>();
		private static readonly string[] TestPatterns = {"abc", "123"};

		private readonly Action<Guid, string> callback;
	}
}