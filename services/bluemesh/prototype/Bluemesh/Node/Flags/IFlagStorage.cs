using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Node.Serialization;

namespace Node.Flags
{
    internal interface IFlagStorage : IBinarySerializable
    {
        string GetHash();

        int Version { get; }

        IFlagStorage Put(string flag);

        IFlagStorage Merge(IFlagStorage other);

        IEnumerable<string> Flags { get; } 
    }
}
