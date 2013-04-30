using System;
using PacketDotNet;
using SharpPcap;
using System.Threading;
using System.Collections.Generic;
using WireSentry.SDK;

namespace WireSentry
{
	public interface IPacketProcessor
	{
		/// <summary>
		/// Processes the specified packet capture.
		/// </summary>
		/// <param name='capture'>
		/// The raw data captured from the interface.
		/// </param>
		DataPacket Process(RawCapture capture);
	}
}