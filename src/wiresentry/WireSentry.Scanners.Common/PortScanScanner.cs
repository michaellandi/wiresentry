using System;
using System.Linq;
using WireSentry.SDK;
using System.Collections.Generic;

namespace XTSec.Scanners.Common
{
	public class PortScanScanner : Scanner
	{
		public PortScanScanner(IDebug debugger) : base(debugger)
		{

		}

		public override IEnumerable<ScannerResult> Scan(IDataPacketCollection packets)
		{
			//Create a list of results we can add to as we find new attacks.
			var results = new List<ScannerResult>();
			
			//Determine the time period that we should look back for packets at.
			var lookback = DateTime.Now.AddMinutes(-1).AddSeconds(-30);
			
			//Group all DNS packets by the sender.
			var tcp_source = packets.Items
				.Where(x => x.Protocol == NetworkProtocol.tcp)
				.Where(x => x.Timestamp >= lookback).ToLookup(x => x.IpAddressSource);
			
			foreach (var ip_source in tcp_source.Select(x => x.Key))
			{
				var tcp_destination = tcp_source[ip_source].ToLookup(x => x.IpAddressDestination);

				foreach (var ip_destination in tcp_destination.Select(x => x.Key))
				{
					var matches = tcp_destination[ip_destination].OrderBy(x => x.PortDestination);
					var ports = matches.Select(x => x.PortDestination).ToArray();

					var longestSequence = LIS(ports);

					if (longestSequence > 30)
					{
						//Store the packets and result in the list for return.
						var offendingPacket = matches.First();
						var result = new ScannerResult(offendingPacket.HardwareAddressSource,
						                               offendingPacket.HardwareAddressTarget,
						                               "Port Scan",
						                               this,
						                               matches);

						results.Add(result);
					}
				}
				
			}

			return results;
		}

		private int LIS(int[] sequence) 
		{
			int max = int.MinValue;
			int[] l = new int[sequence.Length];
			int[] p = new int[sequence.Length];
			
			l[0] = 1;
			
			for (int i=0; i<sequence.Length; i++)
				p[i] = -1;
			
			for (int i = 1; i < sequence.Length; i++)
			{
				l[i] = 1;
				for (int j = 0; j < i; j++)
				{
					if (sequence[j] < sequence[i] && l[j] + 1 > l[i])
					{
						l[i] = l[j] + 1;
						p[i] = j;
						if (l[i] > max)
							max = l[i];
					}
				}
			}

			return max;
		}

		public override int Frequency
		{
			get
			{
				return 5;
			}
		}

		public override Guid Id
		{
			get
			{
				return new Guid("7fbaa4ca-be2c-4234-9ecc-e4b63c7d1d70");
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
				return "Port Scan Scanner";
			}
		}

		public override string Version
		{
			get
			{
				return "0.0.9";
			}
		}
	}
}

