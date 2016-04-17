using System;
using System.IO;
using System.Text;

namespace Node.Serialization
{
    internal class StreamDeserializer : IBinaryDeserializer
    {
        public StreamDeserializer(Stream stream)
        {
            this.stream = stream;
        }

        public byte[] ReadBytes()
        {
            var length = ReadInt();
            try
            {
                if (stream.CanSeek && length > stream.Length - stream.Position)
                {
                    //Console.WriteLine("Tried to read too much data!");
                    length = (int) (stream.Length - stream.Position);
                }
            }
            catch
            {
            }
            var buffer = new byte[length];
            stream.Read(buffer, 0, length);
            return buffer;
        }

        public string ReadString()
        {
            return Encoding.UTF8.GetString(ReadBytes());
        }

        public int ReadInt()
        {
            var buffer = new byte[4];
            stream.Read(buffer, 0, 4);
            return BitConverter.ToInt32(buffer, 0);
        }

        public T Read<T>(Func<IBinaryDeserializer, T> readFunc)
        {
            return readFunc(this);
        }

        private readonly Stream stream;
    }
}