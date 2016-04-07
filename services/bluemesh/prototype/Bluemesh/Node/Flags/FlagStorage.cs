using System.Collections.Generic;
using System.Linq;
using Node.Serialization;

namespace Node.Flags
{
    internal class FlagStorage : IFlagStorage
    {
        public FlagStorage() : this(new HashSet<string>()) { }

        private FlagStorage(HashSet<string> flags)
        {
            this.flags = flags;
        }

        public void Serialize(IBinarySerializer serializer)
        {
            foreach (var flag in flags)
                serializer.Write(flag);
        }

        public string GetHash()
        {
            var multiplier = 1;
            return flags.OrderBy(f => f)
                .Aggregate(0, (hash, flag) => (hash * (multiplier *= 167)) ^ flag.GetHashCode())
                .ToString("x8");
        }

        public IFlagStorage Put(string flag)
        {
            return new FlagStorage(new HashSet<string>(flags.Union(new[] { flag })));
        }

        public IFlagStorage Merge(IFlagStorage other)
        {
            return new FlagStorage(new HashSet<string>(flags.Union(other.Flags)));
        }

        public IEnumerable<string> Flags => flags;

        public int Version => flags.Count;

        private readonly HashSet<string> flags;
    }
}