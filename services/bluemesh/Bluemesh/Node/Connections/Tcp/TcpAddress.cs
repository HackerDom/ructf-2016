using System.Net;
using Node.Serialization;

namespace Node.Connections.Tcp
{
    internal class TcpAddress : IAddress
    {
        public TcpAddress(IPEndPoint endpoint)
        {
            Endpoint = endpoint;
        }
        
        public override string ToString()
        {
            return Endpoint.ToString();
        }

        protected bool Equals(TcpAddress other)
        {
            return Equals(Endpoint, other.Endpoint);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((TcpAddress) obj);
        }

        public override int GetHashCode()
        {
            return Endpoint.GetHashCode();
        }

        public void Serialize(IBinarySerializer serializer)
        {
            serializer.Write(Endpoint.Address.GetAddressBytes());
            serializer.Write(Endpoint.Port);
        }

        public readonly IPEndPoint Endpoint;
    }
}