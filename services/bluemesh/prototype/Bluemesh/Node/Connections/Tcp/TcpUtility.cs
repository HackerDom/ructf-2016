using System.Net;
using Node.Serialization;

namespace Node.Connections.Tcp
{
    internal class TcpUtility : IConnectionUtility
    {
        public IAddress ParseAddress(string s)
        {
            var parts = s.Split(':');
            return new TcpAddress(new IPEndPoint(IPAddress.Parse(parts[0]), int.Parse(parts[1])));
        }

        public IAddress DeserializeAddress(IBinaryDeserializer deserializer)
        {
            return new TcpAddress(new IPEndPoint(new IPAddress(deserializer.ReadBytes()), deserializer.ReadInt()));
        }
    }
}