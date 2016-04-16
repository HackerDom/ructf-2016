using Node.Serialization;

namespace Node.Data
{
    internal interface IDataStorage : IBinarySerializable
    {
        void PutData(string key, byte[] data);
        byte[] GetData(string key);
    }
}
