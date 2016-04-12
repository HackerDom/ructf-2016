using Node.Serialization;

namespace Node.Connections
{
    internal interface IConnectionUtility
    {
        IAddress ParseAddress(string s);
        IAddress DeserializeAddress(IBinaryDeserializer deserializer);
    }
}