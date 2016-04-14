using Node.Encryption;
using Node.Serialization;

namespace Node.Messages
{
    internal class DataMessage : IMessage
    {
        public DataMessage(DataAction action, string key, byte[] data)
        {
            Action = action;
            Key = key;
            Data = data;
        }

        public void Serialize(IBinarySerializer serializer)
        {
            serializer.Write((int)Action);
            serializer.Write(Key);
            serializer.Write(Data);
        }

        public DataMessage Deserialize(IBinaryDeserializer deserializer)
        {
            return new DataMessage(
                (DataAction) deserializer.ReadInt(),
                deserializer.ReadString(),
                deserializer.ReadBytes());
        }

        public MessageType Type => MessageType.Data;

        public readonly DataAction Action;
        public readonly string Key;
        public readonly byte[] Data;
    }
}