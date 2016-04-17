using Node.Serialization;

namespace Node.Messages
{
    internal class StringMessage : IMessage
    {
        public StringMessage(string text)
        {
            Text = text;
        }
        public string Text { get; }

        public void Serialize(IBinarySerializer serializer)
        {
            serializer.Write(Text);
        }

        public static StringMessage Deserialize(IBinaryDeserializer deserializer)
        {
            return new StringMessage(deserializer.ReadString());
        }

        public override string ToString()
        {
            return Text;
        }

        protected bool Equals(StringMessage other)
        {
            return string.Equals(Text, other.Text);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((StringMessage) obj);
        }

        public override int GetHashCode()
        {
            return Text.GetHashCode();
        }

        public MessageType Type => MessageType.String;
    }
}