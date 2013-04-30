using System;
using WireSentry.SDK;

namespace WireSentry
{
	public class NullLogger : IPacketLogger
	{
		#region IPacketLogger implementation

		public void Open()
		{

		}

		public void Close()
		{

		}

		public void Create(ScannerResult result)
		{

		}

		public void Update(ScannerResult result)
		{

		}

		#endregion
	}
}

