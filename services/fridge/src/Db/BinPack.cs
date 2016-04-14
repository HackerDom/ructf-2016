using System;
using System.IO;
using System.Text;

namespace frɪdʒ.Db
{
	internal class BinPack
	{
		public BinPack()
		{
			stream = new MemoryStream();
		}

		public BinPack Write(int val)
		{
			return WriteBytesRaw(BitConverter.GetBytes(val));
		}

		public BinPack Write(Guid val)
		{
			return WriteBytesRaw(val.ToByteArray());
		}

		public BinPack Write(string value)
		{
			return Write(Encoding.UTF8.GetBytes(value));
		}

		public BinPack Write(string[] values)
		{
			var pack = Write(values.Length);
			for(int i = 0; i < values.Length; i++)
				pack = Write(values[i]);
			return pack;
		}

		public BinPack Write(byte[] buffer)
		{
			return Write(buffer, 0, buffer.Length);
		}

		public BinPack Write(byte[] buffer, int offset, int count)
		{
			return Write(count).WriteBytesRaw(buffer, offset, count);
		}

		public byte[] ToArray()
		{
			var buffer = stream.GetBuffer();
			return stream.Length == buffer.Length ? buffer : stream.ToArray();
		}

		private BinPack WriteBytesRaw(byte[] buffer)
		{
			return WriteBytesRaw(buffer, 0, buffer.Length);
		}

		private BinPack WriteBytesRaw(byte[] buffer, int offset, int count)
		{
			stream.Write(buffer, offset, count);
			return this;
		}

		private readonly MemoryStream stream;
	}

	public class BinUnpack
	{
		public BinUnpack(byte[] buffer)
		{
			this.buffer = buffer;
		}

		public int ReadInt32()
		{
			var value = BitConverter.ToInt32(buffer, position);
			position += sizeof(int);
			return value;
		}

		public Guid ReadGuid()
		{
			var tmp = new byte[GuidLength];
			Buffer.BlockCopy(buffer, position, tmp, 0, GuidLength);
			position += GuidLength;
			return new Guid(tmp);
		}

		public string ReadString()
		{
			var length = ReadInt32();
			var value = Encoding.UTF8.GetString(buffer, position, length);
			position += length;
			return value;
		}

		public string[] ReadStringArray()
		{
			var result = new string[ReadInt32()];
			for(int i = 0; i < result.Length; i++)
				result[i] = ReadString();
			return result;
		}

		private const int GuidLength = 16;

		private readonly byte[] buffer;
		private int position;
	}
}