using System.Collections.Generic;
using System.Linq;
using System.Text;
using Node.Serialization;

namespace Node.Data
{
    internal class DataStorage : IDataStorage
    {
        public DataStorage(Dictionary<string, byte[]> data)
        {
            this.data = data;
        }

        public DataStorage() : this(new Dictionary<string, byte[]>()) { }

        public void Serialize(IBinarySerializer serializer)
        {
            serializer.WriteList(data, (d, pair) =>
            {
                d.Write(Encoding.UTF8.GetBytes(pair.Key));
                d.Write(pair.Value);
            });
        }

        public static DataStorage Deserialize(IBinaryDeserializer deserializer)
        {
            return new DataStorage(deserializer.ReadList(d => new
            {
                Key = Encoding.UTF8.GetString(deserializer.ReadBytes()),
                Value = deserializer.ReadBytes()
            }).ToDictionary(x => x.Key, x => x.Value));
        }

        public void PutData(string key, byte[] value)
        {
            if (!data.ContainsKey(key))
                data[key] = value;
        }

        public byte[] GetData(string key)
        {
            byte[] value;
            return data.TryGetValue(key, out value) ? value : null;
        }

        public override string ToString()
        {
            return string.Join(", ", data.Keys);
        }

        private readonly Dictionary<string, byte[]> data;
    }
}