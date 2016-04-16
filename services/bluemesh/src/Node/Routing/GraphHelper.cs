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
            return links.Where(link => link.Connected && link.Contains(source)).Select(link => link.OtherEnd(source));
        }

        public static HashSet<IAddress> GetNodes(ICollection<RoutingMapLink> links)
        {
            var nodes = new HashSet<IAddress>();
            foreach (var link in links.Where(l => l.Connected))
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

        public static string ToDOT(this IEnumerable<RoutingMapLink> links, string name = "", bool longNames = false)
        {
            return
                $@"
graph {name} {{
{string.Join(Environment.NewLine, links.Where(l => l.Connected).Select(link => "\t" + MakeSafeString(link.A, longNames) + " -- " + MakeSafeString(link.B, longNames) + "; // v: " + link.Version))}
}}";
        }

        public static bool AreEquivalent(this ICollection<RoutingMapLink> myLinks, ICollection<RoutingMapLink> otherLinks)
        {
            if (myLinks.Count != otherLinks.Count)
                return false;

            return myLinks.All(myLink => otherLinks.Any(otherLink => Equals(myLink, otherLink) && myLink.Connected == otherLink.Connected));
        }

        //TODO make random path
        public static List<IAddress> CreatePath(this ICollection<RoutingMapLink> links, IAddress from, IAddress to)
        {
            return CreatePath(to, from, links, new HashSet<IAddress>()).Reverse().ToList();
        }

        public static List<IAddress> GetPathBody(this IList<IAddress> path)
        {
            return path.Skip(2).Take(path.Count - 2).ToList();
        }

        public static List<IAddress> CreateRandomPath(this ICollection<RoutingMapLink> links, IAddress from, IAddress to, int minLength, int maxLength, Random random)
        {
            var candidateNodes = new HashSet<IAddress>();
            if (!FindPathCandidateNodes(from, to, links, new HashSet<IAddress>(), candidateNodes))
                return null;

            var pathNodes = new List<IAddress>();
            return BuildRandomPath(from, to, links, candidateNodes, pathNodes, minLength, maxLength, random) ? pathNodes : null;
        }

        private static string MakeSafeString(object obj, bool longNames)
        {
            if (obj is TcpAddress && !longNames)
                return (((TcpAddress) obj).Endpoint.Port % 100).ToString();
            return obj.ToString().Replace(".", "").Replace(":", "");
        }

        private static IEnumerable<IAddress> CreatePath(IAddress destination, IAddress source, ICollection<RoutingMapLink> links, HashSet<IAddress> visitedNodes)
        {
            if (Equals(source, destination))
                yield return destination;
            else
            {
                visitedNodes.Add(source);

                foreach (var peer in GetPeers(source, links).Where(peer => !visitedNodes.Contains(peer)))
                {
                    var found = false;
                    foreach (var address in CreatePath(destination, peer, links, visitedNodes))
                    {
                        yield return address;
                        found = true;
                    }
                    if (found)
                    {
                        yield return source;
                        break;
                    }
                }
            }
        }

        private static bool BuildRandomPath(IAddress source, IAddress destination, ICollection<RoutingMapLink> links, HashSet<IAddress> candidateNodes, List<IAddress> pathNodes, int minLength, int maxLength, Random random)
        {
            pathNodes.Add(source);

            if (Equals(source, destination) && pathNodes.Count >= minLength)
                return true;

            if (pathNodes.Count >= maxLength)
            {
                pathNodes.RemoveAt(pathNodes.Count - 1);
                return false;
            }

            var peers = GetPeers(source, links).Where(candidateNodes.Contains).ToList();
            while (true)
            {
                var peer = peers[random.Next(peers.Count)];
                if (BuildRandomPath(peer, destination, links, candidateNodes, pathNodes, minLength, maxLength, random))
                    return true;
            }
        }

        private static bool FindPathCandidateNodes(IAddress source, IAddress destination, ICollection<RoutingMapLink> links, HashSet<IAddress> visitedNodes, HashSet<IAddress> candidateNodes)
        {
            visitedNodes.Add(source);
            if (Equals(source, destination))
            {
                candidateNodes.Add(source);
                return true;
            }
            var found = false;
            foreach (var peer in GetPeers(source, links).Where(p => !visitedNodes.Contains(p)))
            {
                if (FindPathCandidateNodes(peer, destination, links, visitedNodes, candidateNodes))
                    found = true;
            }
            if (found)
                candidateNodes.Add(source);
            return found;
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