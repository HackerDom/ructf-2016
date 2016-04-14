using System;
using Node.Connections;

namespace Node.Routing
{
    internal static class TimespanExtensions
    {
        public static TimeSpan AdjustForNode(this TimeSpan timeSpan, IAddress nodeAddress)
        {
            return timeSpan + TimeSpan.FromTicks((long) (timeSpan.Ticks * new Random(nodeAddress.GetHashCode()).NextDouble()));
        }
    }
}