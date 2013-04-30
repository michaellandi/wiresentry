using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using WireSentry.SDK;

namespace XTSec.Scanners.Common
{
	public class DnsSpoofScanner : Scanner
	{
		public DnsSpoofScanner(IDebug debugger) : base(debugger) { }

		#region implemented abstract members of Scanner

		public override System.Collections.Generic.IEnumerable<ScannerResult> Scan(IDataPacketCollection packets)
		{
			//Create a list of results we can add to as we find new attacks.
			var results = new List<ScannerResult>();
			
			//Determine the time period that we should look back for packets at.
			var lookback = DateTime.Now.AddMinutes(-1).AddSeconds(-30);
			
			//Group all DNS packets by the sender.
			var dns_source = packets.Items
				.Where(x => x.Protocol == NetworkProtocol.udp)
				.Where(x => x.PortSource == 53)
				.Where(x => x.Timestamp >= lookback).ToLookup(x => x.HardwareAddressSource);

			foreach (var mac_source in dns_source.Select(x => x.Key))
			{



			}

			return results;
		}

		public override Guid Id
		{
			get
			{
				return new Guid("a30b4de2-84e4-4209-956f-d64376e1011");
			}
		}
		
		public override int Frequency
		{
			get
			{
				return 5;
			}
		}
		
		public override string Author
		{
			get
			{
				return "Michael Landi";
			}
		}
		
		public override string Name
		{
			get
			{
				return "DNS Spoof Scanner";
			}
		}
		
		public override string Version
		{
			get
			{
				return "1.00.00.00";
			}
		}

		#endregion
	}
}

