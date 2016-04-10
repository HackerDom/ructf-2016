using Node.Serialization;

namespace Node.Messages
{
    class HelloMessage : IMessage
    {
        public void Serialize(IBinarySerializer serializer)
        {
        }

        public MessageType Type => MessageType.Hello;
    }
}