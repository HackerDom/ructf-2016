namespace Node.Serialization
{
    internal interface IBinarySerializable
    {
        void Serialize(IBinarySerializer serializer);
    }
}