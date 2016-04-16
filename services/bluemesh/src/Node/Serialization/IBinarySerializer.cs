using System;

namespace Node.Serialization
{
    internal interface IBinarySerializer
    {
        void Write(IBinarySerializable serializable);
        void Write<T>(T value, Action<T, IBinarySerializer> writeAction);
        void Write(byte[] bytes);
        void Write(int value);
        void Write(string value);
    }
}