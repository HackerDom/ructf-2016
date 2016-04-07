using System;
using System.Net;
using Node.Serialization;

namespace Node.Connections.LocalTcp
{
    internal class LocalTcpAddress : IAddress
    {
        public LocalTcpAddress(int id)
        {
            if (id >= MinPort && id <= MaxPort)
                Port = id;
            else if (id >= 0 && id < 100)
                Port = id + MinPort;
            else
                throw new ArgumentOutOfRangeException(nameof(id));
        }

        public int Port { get; }

        public override string ToString()
        {
            return (Port - MinPort).ToString();
        }

        protected bool Equals(LocalTcpAddress other)
        {
            return Port == other.Port;
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((LocalTcpAddress) obj);
        }

        public override int GetHashCode()
        {
            return Port;
        }

        public void Serialize(IBinarySerializer serializer)
        {
            serializer.Write(Port);
        }

        public IPEndPoint ToEndpoint()
        {
            return new IPEndPoint(IPAddress.Loopback, Port);
        }

        public const int MinPort = 16800;
        public const int MaxPort = 16899;
    }
}