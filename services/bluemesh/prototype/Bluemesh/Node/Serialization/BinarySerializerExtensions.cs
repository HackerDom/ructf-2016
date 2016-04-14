using System;
using System.Collections.Generic;

namespace Node.Serialization
{
    internal static class BinarySerializerExtensions
    {
        public static void WriteList<T>(this IBinarySerializer serializer, ICollection<T> list) where T : IBinarySerializable
        {
            serializer.Write(list.Count);
            foreach (var item in list)
                serializer.Write(item);
        }
        public static void WriteList<T>(this IBinarySerializer serializer, ICollection<T> list, Action<IBinarySerializer, T> serializeFunc)
        {
            serializer.Write(list.Count);
            foreach (var item in list)
                serializeFunc(serializer, item);
        }
    }
}