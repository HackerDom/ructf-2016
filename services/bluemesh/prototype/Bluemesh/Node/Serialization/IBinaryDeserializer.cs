using System;

namespace Node.Serialization
{
    internal interface IBinaryDeserializer
    {
        byte[] ReadBytes();

        int ReadInt();

        T Read<T>(Func<IBinaryDeserializer, T> readFunc);
    }
}