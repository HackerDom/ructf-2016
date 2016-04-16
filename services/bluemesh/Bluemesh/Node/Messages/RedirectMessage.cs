using Node.Connections;
using Node.Serialization;

namespace Node.Messages
{
    internal class RedirectMessage : IMessage
    {
        public RedirectMessage(IAddress destination, byte[] data)
        {
            Destination = destination;
            Data = data;
        }

        public void Serialize(IBinarySerializer serializer)
        {
            serializer.Write(Destination);
            serializer.Write(Data);
        }

        public static RedirectMessage Deserialize(IBinaryDeserializer deserializer, IConnectionUtility utility)
        {
            return new RedirectMessage(utility.DeserializeAddress(deserializer), deserializer.ReadBytes());
        }

        public MessageType Type => MessageType.Redirect;

        public readonly IAddress Destination;
        public readonly byte[] Data;
    }
}