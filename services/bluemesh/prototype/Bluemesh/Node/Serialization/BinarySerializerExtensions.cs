using System.Collections.Generic;

namespace Node.Serialization
{
    internal static class BinarySerializerExtensions
    {
        public static void WriteList<T>(this IBinarySerializer serializer, IList<T> list) where T : IBinarySerializable
        {
            serializer.Write(list.Count);
            foreach (var item in list)
                serializer.Write(item);
        }
    }
}