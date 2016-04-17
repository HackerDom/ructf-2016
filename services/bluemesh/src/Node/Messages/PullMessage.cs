using Node.Serialization;

namespace Node.Messages
{
    internal class PullMessage : IMessage
    {
        public PullMessage(int limit)
        {
            Limit = limit;
        }

        public void Serialize(IBinarySerializer serializer)
        {
            serializer.Write(Limit);
        }

        public static PullMessage Deserialize(IBinaryDeserializer deserializer)
        {
            return new PullMessage(deserializer.ReadInt());
        }

        public MessageType Type => MessageType.Pull;

        public readonly int Limit;
    }
}