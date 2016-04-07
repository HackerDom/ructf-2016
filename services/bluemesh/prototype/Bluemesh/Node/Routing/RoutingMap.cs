using System.Collections.Generic;
using System.Linq;
using Node.Connections;
using Node.Serialization;

namespace Node.Routing
{
    internal class RoutingMap : IRoutingMap
    {
        public RoutingMap(IAddress ownAddress, IRoutingConfig config)
        {
            this.config = config;
            OwnAddress = ownAddress;
            Links = new HashSet<RoutingMapLink>();
        }

        public RoutingMap(IAddress ownAddress, IEnumerable<RoutingMapLink> links, IRoutingConfig config)
        {
            this.config = config;
            OwnAddress = ownAddress;
            Links = new HashSet<RoutingMapLink>(links);
        }

        public IAddress FindExcessPeer()
        {
            var stateBefore = GraphHelper.CalculateConnectivity(Links);

            IAddress excessPeer = null;
            foreach (var peerLink in Links.Where(link => link.Contains(OwnAddress)).ToList())
            {
                Links.Remove(peerLink);
                var stateAfter = GraphHelper.CalculateConnectivity(Links);
                Links.Add(peerLink);

                if (Equals(stateAfter, stateBefore))
                {
                    excessPeer = peerLink.OtherEnd(OwnAddress);
                    break;
                }
            }

            return excessPeer;
        }

        public void Merge(IEnumerable<RoutingMapLink> links)
        {
            var countBefore = Links.Count;
            Links.UnionWith(links);
            if (Links.Count > countBefore)
                Version++;
        }

        public void AddDirectConnection(IAddress other)
        {
            var peerCount = GraphHelper.GetPeers(OwnAddress, Links).Count();
            if (peerCount >= config.MaxConnections)
                return;

            var newLink = new RoutingMapLink(OwnAddress, other);
            if (GraphHelper.IsReachable(other, OwnAddress, Links))
            {
                if (peerCount >= config.DesiredConnections)
                    return;

                var stateBefore = GraphHelper.CalculateConnectivity(Links);
                Links.Add(newLink);
                var stateAfter = GraphHelper.CalculateConnectivity(Links);

                if (Equals(stateAfter, stateBefore))
                {
                    Links.Remove(newLink);
                    return;
                }
            }
            else
                Links.Add(newLink);
            Version++;
        }

        public void RemoveDirectConnection(IAddress other)
        {
            if (Links.Remove(new RoutingMapLink(OwnAddress, other)))
                Version++;
        }

        public IAddress OwnAddress { get; }

        public override string ToString()
        {
            return Links.ToDOT("routes");
        }

        public HashSet<RoutingMapLink> Links { get; }

        public int Version { get; private set; }

        private readonly IRoutingConfig config;
    }
}