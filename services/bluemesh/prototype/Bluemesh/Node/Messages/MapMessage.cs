using System.Collections.Generic;
using System.Linq;
using Node.Connections;
using Node.Routing;
using Node.Serialization;

namespace Node.Messages
{
    internal class MapMessage : IMessage
    {

        public MapMessage(IEnumerable<RoutingMapLink> links, bool suggestDisconnect)
        {
            SuggestDisconnect = suggestDisconnect;
            Links = links.ToList();
        }

        public void Serialize(IBinarySerializer serializer)
        {
            serializer.WriteList(Links);
            serializer.Write(SuggestDisconnect ? 1 : 0);
        }

        public static MapMessage Deserialize(IBinaryDeserializer deserializer, IConnectionUtility utility)
        {
            return new MapMessage(deserializer.ReadList(d => RoutingMapLink.Deserialize(deserializer, utility)), deserializer.ReadInt() != 0);
        }

        public MessageType Type => MessageType.Map;

        public List<RoutingMapLink> Links { get; }
        public bool SuggestDisconnect { get; }
    }
}