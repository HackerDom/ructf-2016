using System;
using System.Collections.Concurrent;
using System.Net;
using System.Threading.Tasks;

using frɪdʒ.utils;

namespace frɪdʒ.http
{
	internal static class FoodHandler
	{
		public static async Task ProcessPutRequestAsync(HttpListenerContext context)
		{
			var data = await context.Request.ReadStringAsync();
			if(data == null)
				return;

			var id = Guid.NewGuid().ToString("N");
			Db[id] = data;

			var result = id + ":" + string.Join(",", data.FindAll(TestPatterns));
			await context.Response.WriteStringAsync(result);
		}

		public static async Task ProcessGetRequestAsync(HttpListenerContext context)
		{
			var id = context.Request.QueryString["id"];

			var data = Db.GetOrDefault(id);
			if(data == null)
				throw new HttpException(404, "Food not found");

			await context.Response.WriteStringAsync(data);
		}

		private static readonly ConcurrentDictionary<string, string> Db = new ConcurrentDictionary<string, string>();
		private static readonly string[] TestPatterns = {"abc", "123"};
	}
}