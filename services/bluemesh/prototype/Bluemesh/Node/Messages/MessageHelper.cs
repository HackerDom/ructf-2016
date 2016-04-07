using System;
using Node.Serialization;

namespace Node.Messages
{
    internal static class MessageHelper
    {
        public static Func<IBinaryDeserializer, IMessage> GetDeserializeMethod(MessageType type)
        {
            switch (type)
            {
                case MessageType.String:
                    return StringMessage.DeserializeBinary;
                default:
                    throw new ArgumentOutOfRangeException("Unknown message type: " + type);
            }
        }
    }
}