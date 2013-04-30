using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using WireSentry.SDK;

namespace WireSentry.Scanners.Common
{
	public class ArpSpoofScanner : Scanner
	{
		public ArpSpoofScanner(IDebug debugger) : base(debugger) { }

		#region implemented abstract members of Scanner

		public override IEnumerable<ScannerResult> Scan(IDataPacketCollection packets)
		{
			//Create a list of results we can add to as we find new attacks.
			var results = new List<ScannerResult>();
			//Determine the time period that we should look back for packets at.
			var lookback = DateTime.Now.AddMinutes(-1).AddSeconds(-30);
			//Group all ARP packets by the sender.
			var arp_source = packets.Items.Where(
				x => x.Protocol == NetworkProtocol.arp).ToLookup(
					x => x.HardwareAddressSource);

			//Loop through each source address.
			foreach (string mac_source in arp_source.Select(x => x.Key))
			{
				//Group all of the sender packets by the target address.
				var arp_source_target = arp_source[mac_source].ToLookup(
					x => x.HardwareAddressTarget);

				//Loop through each target address.
				foreach (var mac_target in arp_source_target.Select(x => x.Key))
				{
					/*
					 * Determine if a certain number of attack packets were found
					 * for this sender/receiver in the lookback time period.
					 */
					if (arp_source_target[mac_target].Where(x => x.Timestamp >= lookback).Count() >= 20)
					{
						//Store the packets and result in the list for return.
						var packet = arp_source_target[mac_target].First();
						var result = new ScannerResult(packet.HardwareAddressSource,
														packet.HardwareAddressTarget,
							 							"ARP Spoof",
														this,
														arp_source_target[mac_target]);

						results.Add(result);
					}
				}
			}

			return results;
		}

		public override Guid Id
		{
			get
			{
				return new Guid("930b4de2-8424-4209-956d-d64d176e1000");
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
				return "Arp Spoof Scanner";
			}
		}

		public override string Version
		{
			get
			{
				return "1.00.00.38";
			}
		}

		#endregion
	}
}

