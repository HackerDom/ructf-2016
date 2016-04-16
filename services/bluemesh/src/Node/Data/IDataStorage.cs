using Node.Serialization;

namespace Node.Data
{
    internal interface IDataStorage : IBinarySerializable
    {
        bool PutData(string key, byte[] data);
        byte[] GetData(string key);
    }
}
