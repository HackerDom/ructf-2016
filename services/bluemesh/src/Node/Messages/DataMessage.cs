using Node.Connections;
using Node.Serialization;

namespace Node.Messages
{
    internal class DataMessage : IMessage
    {
        public DataMessage(DataAction action, string key, byte[] data, IAddress source)
        {
            Action = action;
            Key = key;
            Data = data;
            Source = source;
        }

        public void Serialize(IBinarySerializer serializer)
        {
            serializer.Write((int)Action);
            serializer.Write(Key);
            serializer.Write(Data);
            serializer.Write(Source);
        }

        public static DataMessage Deserialize(IBinaryDeserializer deserializer, IConnectionUtility utility)
        {
            return new DataMessage(
                (DataAction) deserializer.ReadInt(),
                deserializer.ReadString(),
                deserializer.ReadBytes(),
                utility.DeserializeAddress(deserializer));
        }

        public MessageType Type => MessageType.Data;

        public readonly DataAction Action;
        public readonly string Key;
        public readonly byte[] Data;
        public readonly IAddress Source;
    }
}