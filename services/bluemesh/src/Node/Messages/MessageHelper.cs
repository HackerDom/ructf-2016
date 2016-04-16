using System;
using Node.Connections;
using Node.Serialization;

namespace Node.Messages
{
    internal static class MessageHelper
    {
        public static Func<IBinaryDeserializer, IMessage> GetDeserializeMethod(MessageType type, IConnectionUtility utility)
        {
            switch (type)
            {
                case MessageType.String:
                    return StringMessage.Deserialize;
                case MessageType.Map:
                    return d => MapMessage.Deserialize(d, utility);
                case MessageType.Data:
                    return d => DataMessage.Deserialize(d, utility);
                case MessageType.Redirect:
                    return d => RedirectMessage.Deserialize(d, utility);
                case MessageType.Pull:
                    return PullMessage.Deserialize;
                default:
                    throw new ArgumentOutOfRangeException("Unknown message type: " + type);
            }
        }
    }
}