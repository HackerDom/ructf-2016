using System;
using System.IO;
using Node.Connections;
using Node.Serialization;

namespace Node.Messages
{
    internal class MessageContainer
    {
        public MessageContainer(IMessage message)
        {
            this.message = message;
        }
        public int WriteToBuffer(byte[] buffer, int offset)
        {
            using (var stream = new MemoryStream())
            {
                var serializer = new StreamSerializer(stream);
                serializer.Write(0);
                serializer.Write((int) message.Type);
                serializer.Write(message);
                var length = (int)stream.Position - HeaderSize;
                stream.Seek(0, SeekOrigin.Begin);
                serializer.Write(length);
                Buffer.BlockCopy(stream.GetBuffer(), 0, buffer, offset, (int) stream.Length);
                return (int) stream.Length;
            }
        }

        public static MessageContainer ReadFromBuffer(byte[] buffer, int offset, IConnectionUtility utility)
        {
            using (var stream = new MemoryStream(buffer, offset, buffer.Length - offset, false))
            {
                var deserializer = new StreamDeserializer(stream);
                deserializer.ReadInt();
                var messageType = (MessageType)deserializer.ReadInt();
                return new MessageContainer(MessageHelper.GetDeserializeMethod(messageType, utility)(deserializer));
            }
        }
        
        public static int GetNeededLength(byte[] buffer, int offset)
        {
            using (var stream = new MemoryStream(buffer, offset, buffer.Length - offset, false))
            {
                var deserializer = new StreamDeserializer(stream);
                var messageLength = deserializer.ReadInt();
                return messageLength + HeaderSize;
            }
        }

        public IMessage Message => message;

        private readonly IMessage message;

        public const int HeaderSize = 8;
    }
}