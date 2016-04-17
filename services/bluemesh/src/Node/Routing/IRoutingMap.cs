using System.Collections.Generic;
using Node.Connections;

namespace Node.Routing
{
    internal interface IRoutingMap
    {
        void AddDirectConnection(IAddress other);

        bool ShouldConnectTo(IAddress other);

        void RemoveDirectConnection(IAddress other);

        IAddress FindExcessPeer();

        bool IsLinkExcess(RoutingMapLink link);

        void Merge(ICollection<RoutingMapLink> links, IAddress source);

        IAddress OwnAddress { get; }

        List<RoutingMapLink> Links { get; } 

        int Version { get; }
    }
}
