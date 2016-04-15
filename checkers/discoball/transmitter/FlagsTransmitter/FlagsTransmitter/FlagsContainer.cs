using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlagsTransmitter
{
	class FlagsContainer
	{
		public void SetFlag(string ip, string flag)
		{
			container[ip] = flag;
		}

		public IEnumerable<string> EnumerateFlagsInfinite()
		{
			while(true)
			{
				foreach(var kvp in container)
				{
					yield return kvp.Value;
				}
			}
		}

		private ConcurrentDictionary<string, string> container = new ConcurrentDictionary<string, string>();
	}
}
