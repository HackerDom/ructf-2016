using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Node.Connections;
using Node.Serialization;

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

        HashSet<RoutingMapLink> Links { get; } 

        int Version { get; }
    }
}
