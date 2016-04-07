using System.Collections.Generic;
using Node.Connections;
using Node.Routing;
using Node.Serialization;

namespace Node.Messages
{
    internal class MapMessage : IMessage
    {
        public MapMessage(List<RoutingMapLink> links)
        {
            Links = links;
        }

        public void Serialize(IBinarySerializer serializer)
        {
            serializer.WriteList(Links);
        }

        public static MapMessage Deserialize(IBinaryDeserializer deserializer, IConnectionUtility utility)
        {
            return new MapMessage(deserializer.ReadList(d => RoutingMapLink.Deserialize(deserializer, utility)));
        }

        public MessageType Type => MessageType.Map;

        public List<RoutingMapLink> Links { get; }
    }
}