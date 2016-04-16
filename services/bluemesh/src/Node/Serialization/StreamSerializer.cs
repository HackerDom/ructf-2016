using System;
using System.IO;
using System.Text;

namespace Node.Serialization
{
    internal class StreamSerializer : IBinarySerializer, IDisposable
    {
        public StreamSerializer(Stream stream)
        {
            this.stream = stream;
        }

        public void Write(IBinarySerializable serializable)
        {
            serializable.Serialize(this);
        }

        public void Write<T>(T value, Action<T, IBinarySerializer> writeAction)
        {
            writeAction(value, this);
        }

        public void Write(byte[] bytes)
        {
            Write(bytes.Length);
            stream.Write(bytes, 0, bytes.Length);
        }

        public void Write(int value)
        {
            stream.Write(BitConverter.GetBytes(value), 0, 4);
        }

        public void Write(string value)
        {
            Write(Encoding.UTF8.GetBytes(value));
        }
        public void Dispose()
        {
            stream.Dispose();
        }

        private readonly Stream stream;
    }
}