using System;
using System.Collections.Generic;

namespace Node.Serialization
{
    internal static class BinaryDeserializerExtensions
    {
        public static List<T> ReadList<T>(this IBinaryDeserializer deserializer, Func<IBinaryDeserializer, T> readFunc)
        {
            var count = deserializer.ReadInt();
            var list = new List<T>(count);
            for (int i = 0; i < count; i++)
                list.Add(deserializer.Read(readFunc));
            return list;
        }
    }
}