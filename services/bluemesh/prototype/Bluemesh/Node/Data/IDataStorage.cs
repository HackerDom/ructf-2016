using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Node.Serialization;

namespace Node.Flags
{
    internal interface IDataStorage : IBinarySerializable
    {
        void PutData(string key, byte[] data);
        byte[] GetData(string key);
    }
}
