using System;
using System.Collections.Generic;
using System.Linq;
using Node.Connections;
using Node.Connections.Tcp;

namespace Node.Routing
{
    internal static class GraphHelper
    {
        public static GraphConnectivity CalculateConnectivity(ICollection<RoutingMapLink> links)
        {
            var visitedNodes = new HashSet<IAddress>();
            var entryTime = new Dictionary<IAddress, int>();
            var bestTime = new Dictionary<IAddress, int>();
            var nodes = GetNodes(links);

            var components = 0;
            var bicomponents = 0;

            while (visitedNodes.Count < nodes.Count)
            {
                components++;
                var source = nodes.First(node => !visitedNodes.Contains(node));
                bicomponents += CountCutPoints(source, links, visitedNodes, entryTime, bestTime, 0, true) + 1;
            }
            
            return new GraphConnectivity(components, bicomponents);
        }

        public static IEnumerable<IAddress> GetPeers(IAddress source, ICollection<RoutingMapLink> links)
        {
            return links.Where(link => link.Contains(source)).Select(link => link.OtherEnd(source));
        }

        public static HashSet<IAddress> GetNodes(ICollection<RoutingMapLink> links)
        {
            var nodes = new HashSet<IAddress>();
            foreach (var link in links)
            {
                nodes.Add(link.A);
                nodes.Add(link.B);
            }
            return nodes;
        }

        public static bool IsReachable(IAddress destination, IAddress source, ICollection<RoutingMapLink> links)
        {
            return IsReachable(destination, source, links, new HashSet<IAddress>());
        }

        public static string ToDOT(this IEnumerable<RoutingMapLink> links, string name = "")
        {
            return
                $@"
graph {name} {{
{string.Join(Environment.NewLine, links.Select(link => "\t" + MakeSafeString(link.A) + " -- " + MakeSafeString(link.B) + ";"))}
}}";
        }

        private static string MakeSafeString(object obj)
        {
            if (obj is TcpAddress)
                return (((TcpAddress) obj).Endpoint.Port % 100).ToString();
            return obj.ToString().Replace(".", "").Replace(":", "");
        }

        private static bool IsReachable(IAddress destination, IAddress source, ICollection<RoutingMapLink> links, HashSet<IAddress> visitedNodes)
        {
            if (Equals(source, destination))
                return true;

            visitedNodes.Add(source);

            return GetPeers(source, links).Any(peer => !visitedNodes.Contains(peer) && IsReachable(destination, peer, links, visitedNodes));
        }

        private static int CountCutPoints(
            IAddress source,
            ICollection<RoutingMapLink> links,
            HashSet<IAddress> visitedNodes,
            Dictionary<IAddress, int> entryTime,
            Dictionary<IAddress, int> bestTime,
            int time,
            bool isRoot)
        {
            visitedNodes.Add(source);

            entryTime[source] = bestTime[source] = time;

            var newPeers = 0;
            var isCutpoint = false;
            var cutpoints = 0;

            foreach (var peer in GetPeers(source, links))
            {
                if (visitedNodes.Contains(peer))
                {
                    bestTime[source] = Math.Min(bestTime[source], entryTime[peer]);
                    continue;
                }

                cutpoints += CountCutPoints(peer, links, visitedNodes, entryTime, bestTime, time + 1, false);

                bestTime[source] = Math.Min(bestTime[source], bestTime[peer]);
                if (!isRoot && bestTime[peer] >= entryTime[source])
                    isCutpoint = true;

                newPeers++;
            }

            if (isRoot && newPeers > 1)
                isCutpoint = true;

            if (isCutpoint)
                cutpoints++;

            return cutpoints;
        }
    }
}