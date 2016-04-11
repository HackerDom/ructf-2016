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
            IAddress excessPeer = null;
            foreach (var peerLink in Links.Where(link => link.Contains(OwnAddress)).ToList())
            {
                if (IsLinkExcess(peerLink))
                {
                    excessPeer = peerLink.OtherEnd(OwnAddress);
                    break;
                }
            }

            return excessPeer;
        }

        public bool IsLinkExcess(RoutingMapLink link)
        {
            var stateBefore = GraphHelper.CalculateConnectivity(Links);
            var nodesBefore = GraphHelper.GetNodes(Links);

            if (!Links.Remove(link))
                return false;

            var stateAfter = GraphHelper.CalculateConnectivity(Links);
            var nodesAfter = GraphHelper.GetNodes(Links);

            Links.Add(link);

            return Equals(stateAfter, stateBefore) && nodesAfter.Count == nodesBefore.Count;
        }

        public void Merge(ICollection<RoutingMapLink> links, IAddress source)
        {
            var countBefore = Links.Count;
            var changed = false;

            Links.UnionWith(links);

            if (Links.Count > countBefore)
                changed = true;
            countBefore = Links.Count;

            Links.RemoveWhere(link => link.Contains(source) && !links.Contains(link));

            if (Links.Count < countBefore)
                changed = true;
            if (changed)
                Version++;
        }

        public void AddDirectConnection(IAddress other)
        {
            var newLink = new RoutingMapLink(OwnAddress, other);
            if (Links.Add(newLink))
                Version++;
        }

        public bool ShouldConnectTo(IAddress other)
        {
            var peers = GraphHelper.GetPeers(OwnAddress, Links).ToList();
            if (peers.Count >= config.MaxConnections || peers.Contains(other))
                return false;

            var newLink = new RoutingMapLink(OwnAddress, other);
            if (GraphHelper.IsReachable(other, OwnAddress, Links))
            {
                if (peers.Count >= config.DesiredConnections)
                    return false;

                var stateBefore = GraphHelper.CalculateConnectivity(Links);
                Links.Add(newLink);
                var stateAfter = GraphHelper.CalculateConnectivity(Links);
                Links.Remove(newLink);

                if (Equals(stateAfter, stateBefore))
                    return false;
            }

            return true;
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