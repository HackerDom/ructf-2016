using Node.Serialization;

namespace Node.Messages
{
    internal interface IMessage : IBinarySerializable
    {
        MessageType Type { get; }
    }
}