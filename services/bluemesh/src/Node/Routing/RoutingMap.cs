using System.Collections.Generic;
using System.Linq;
using Node.Connections;

namespace Node.Routing
{
    internal class RoutingMap : IRoutingMap
    {
        public RoutingMap(IAddress ownAddress, IRoutingConfig config)
        {
            this.config = config;
            OwnAddress = ownAddress;
            Links = new List<RoutingMapLink>();
        }

        public RoutingMap(IAddress ownAddress, IEnumerable<RoutingMapLink> links, IRoutingConfig config)
        {
            this.config = config;
            OwnAddress = ownAddress;
            Links = new List<RoutingMapLink>(links);
        }

        public IAddress FindExcessPeer()
        {
            if (GraphHelper.GetPeers(OwnAddress, Links).Count() <= config.DesiredConnections)
                return null;

            IAddress excessPeer = null;
            foreach (var peerLink in Links.Where(link => link.Connected && link.Contains(OwnAddress)).ToList())
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
            if (!link.Connected)
                return false;

            var stateBefore = GraphHelper.CalculateConnectivity(Links);
            var nodesBefore = GraphHelper.GetNodes(Links);

            Links.Remove(link);

            var stateAfter = GraphHelper.CalculateConnectivity(Links);
            var nodesAfter = GraphHelper.GetNodes(Links);

            Links.Add(link);

            return Equals(stateAfter, stateBefore) && nodesAfter.Count == nodesBefore.Count;
        }

        public void Merge(ICollection<RoutingMapLink> links, IAddress source)
        {
            var oldLinks = Links.ToList();

            var linksToAdd = links.Where(link => !link.Contains(OwnAddress) && 
                    ((link.Contains(source) && link.Connected != Links.FirstOrDefault(l => Equals(l, link)).Connected) ||  
                    link.Version > Links.FirstOrDefault(l => Equals(l, link)).Version)).ToList();

            if (linksToAdd.Count > 0)
                Version++;

            foreach (var link in linksToAdd)
                Links.Remove(link);
            Links.AddRange(linksToAdd);

            foreach (var link in links.Where(l => !l.Connected))
            {
                if (!Links.Contains(link))
                    Links.Add(link);
            }

            //Console.WriteLine("[{0}] MERGE {1} with {2} from {3} => {4}", OwnAddress, 
            //    oldLinks.ToDOT(longNames: config.LongNames), links.ToDOT(longNames: config.LongNames), source, Links.ToDOT(longNames: config.LongNames));
        }

        public void AddDirectConnection(IAddress other)
        {
            var newLink = new RoutingMapLink(OwnAddress, other);
            var existingLink = Links.FirstOrDefault(link => Equals(link, newLink));
            if (!existingLink.Connected)
            {
                Links.Remove(existingLink);
                Links.Add(new RoutingMapLink(OwnAddress, other, existingLink.Version + 1, true));
                Version++;
            }
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

                var existingLink = Links.FirstOrDefault(link => Equals(link, newLink));
                var stateBefore = GraphHelper.CalculateConnectivity(Links);
                Links.Remove(existingLink);
                Links.Add(newLink);
                var stateAfter = GraphHelper.CalculateConnectivity(Links);
                Links.Remove(newLink);
                if (existingLink.A != null)
                    Links.Add(existingLink);

                if (Equals(stateAfter, stateBefore))
                    return false;
            }

            return true;
        }

        public void RemoveDirectConnection(IAddress other)
        {
            var existingLink = Links.FirstOrDefault(link => link.Contains(OwnAddress) && link.Contains(other));
            if (existingLink.Connected)
            {
                Links.Remove(existingLink);
                Links.Add(new RoutingMapLink(existingLink.A, existingLink.B, existingLink.Version + 1, false));
                Version++;
            }
        }

        public IAddress OwnAddress { get; }

        public override string ToString()
        {
            return Links.ToDOT("routes", config.LongNames);
        }

        public List<RoutingMapLink> Links { get; }

        public int Version { get; private set; }

        private readonly IRoutingConfig config;
    }
}