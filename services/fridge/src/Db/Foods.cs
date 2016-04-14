using System;
using System.Collections.Concurrent;
using System.Threading.Tasks;

using frɪdʒ.utils;

namespace frɪdʒ.Db
{
	internal static class Foods
	{
		static Foods()
		{
			Store = new DiskStore("data/foods.db", data =>
			{
				var food = Food.Deserialize(data);
				Db[food.Id] = food.Ingredients;
			});
		}

		public static async Task<Guid> Add(string food)
		{
			var id = Guid.NewGuid();
			await Store.WriteAsync(new Food {Id = id, Ingredients = food}.Serialize());
			Db[id] = food;
			return id;
		}

		public static string Find(Guid id)
		{
			return Db.GetOrDefault(id);
		}

		private static readonly ConcurrentDictionary<Guid, string> Db = new ConcurrentDictionary<Guid, string>();
		private static readonly DiskStore Store;
	}

	internal class Food
	{
		public byte[] Serialize()
		{
			return new BinPack().Write(Id).Write(Ingredients).ToArray();
		}

		public static Food Deserialize(byte[] buffer)
		{
			var unpack = new BinUnpack(buffer);
			return new Food
			{
				Id = unpack.ReadGuid(),
				Ingredients = unpack.ReadString()
			};
		}

		public Guid Id;
		public string Ingredients;
	}
}