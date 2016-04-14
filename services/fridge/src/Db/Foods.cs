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
				Db[food.Id] = food;
			});
		}

		public static async Task<Food> Add(string title, string ingredients)
		{
			var id = Guid.NewGuid();
			var food = new Food {Id = id, Title = title, Ingredients = ingredients};
			await Store.WriteAsync(food.Serialize());
			Db[id] = food;
			return food;
		}

		public static Food Find(Guid id)
		{
			return Db.GetOrDefault(id);
		}

		private static readonly ConcurrentDictionary<Guid, Food> Db = new ConcurrentDictionary<Guid, Food>();
		private static readonly DiskStore Store;
	}

	internal class Food
	{
		public byte[] Serialize()
		{
			return new BinPack().Write(Id).Write(Title).Write(Ingredients).ToArray();
		}

		public static Food Deserialize(byte[] buffer)
		{
			var unpack = new BinUnpack(buffer);
			return new Food
			{
				Id = unpack.ReadGuid(),
				Title = unpack.ReadString(),
				Ingredients = unpack.ReadString()
			};
		}

		public Guid Id;
		public string Title;
		public string Ingredients;
	}
}