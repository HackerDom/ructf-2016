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

        void RemoveDirectConnection(IAddress other);

        IAddress FindExcessPeer();

        void Merge(IEnumerable<RoutingMapLink> links);

        IAddress OwnAddress { get; }

        HashSet<RoutingMapLink> Links { get; } 

        int Version { get; }
    }
}
