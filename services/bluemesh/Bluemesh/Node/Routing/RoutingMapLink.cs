using System;
using Node.Connections;
using Node.Serialization;

namespace Node.Routing
{
    internal struct RoutingMapLink : IBinarySerializable
    {
        public RoutingMapLink(IAddress a, IAddress b, int version, bool connected)
        {
            if (a == null || b == null)
                throw new ArgumentException("Links ends must not be null!");
            A = a;
            B = b;
            Version = version;
            Connected = connected;
        }


        public RoutingMapLink(IAddress a, IAddress b)
            : this (a, b, 1, true)
        {
        }

        public readonly IAddress A;
        public readonly IAddress B;
        public readonly int Version;
        public readonly bool Connected;

        public bool Contains(IAddress address)
        {
            return Equals(A, address) || Equals(B, address);
        }

        public IAddress OtherEnd(IAddress address)
        {
            return Equals(A, address) ? B : A;
        }

        public bool Equals(RoutingMapLink other)
        {
            return Equals(A, other.A) && Equals(B, other.B) || Equals(A, other.B) && Equals(B, other.A);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            return obj is RoutingMapLink && Equals((RoutingMapLink) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                return (A?.GetHashCode() ?? 0) ^ (B?.GetHashCode() ?? 0);
            }
        }

        public void Serialize(IBinarySerializer serializer)
        {
            serializer.Write(A);
            serializer.Write(B);
            serializer.Write(Version);
            serializer.Write(Connected ? 1 : 0);
        }

        public static RoutingMapLink Deserialize(IBinaryDeserializer deserializer, IConnectionUtility utility)
        {
            return new RoutingMapLink(utility.DeserializeAddress(deserializer), utility.DeserializeAddress(deserializer), deserializer.ReadInt(), deserializer.ReadInt() != 0);
        }
    }
}