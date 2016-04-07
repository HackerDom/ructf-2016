using Node.Connections;
using Node.Serialization;

namespace Node.Routing
{
    internal struct RoutingMapLink : IBinarySerializable
    {
        public RoutingMapLink(IAddress a, IAddress b)
        {
            A = a;
            B = b;
        }

        public readonly IAddress A;
        public readonly IAddress B;

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
        }
    }
}