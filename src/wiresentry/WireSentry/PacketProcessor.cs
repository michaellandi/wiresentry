using System;
using System.Collections.Generic;
using System.Threading;
using PacketDotNet;
using SharpPcap;
using WireSentry.SDK;

namespace WireSentry
{
	public class PacketProcessor : IPacketProcessor
	{
		protected IDnsProvider Dns { get; set; }
		protected Queue<DataPacket> DnsLookupQueue { get; set; }
		protected EventWaitHandle WaitHandle { get; set; }

		/// <summary>
		/// Initializes a new instance of the <see cref="WireSentry.PacketProcessor"/> class.
		/// </summary>
		/// <param name='dns'>
		/// The DNS Provider which handles DNS lookups for the packets.
		/// </param>
		public PacketProcessor(IDnsProvider dns)
		{
			Dns = dns;
			DnsLookupQueue = new Queue<DataPacket>();
			WaitHandle = new EventWaitHandle(false, EventResetMode.AutoReset);

			//Create a bBackground thread to handle DNS lookups for packets
			new Thread(() => {
				while (true) 
				{
					//Wait until an element has entered the work queue.
					WaitHandle.WaitOne();

					lock (DnsLookupQueue)
					{
						/*
						 * Continue pulling items out of the Queue while items exist
						 * in the queue.  Stop once the Queue is empty and wait for more items
						 * to enter.
						 * 
						 * Once the packet is dequeued, attempt to reverse-dns lookup the source
						 * and destination addresses and add them to the existing packet.
						 */
						while (DnsLookupQueue.Count != 0)
						{
							var dpacket = DnsLookupQueue.Dequeue();
							dpacket.DomainSource = Dns.Get(dpacket.IpAddressSource);
							dpacket.DomainDestination = Dns.Get(dpacket.IpAddressDestination);
						}
					}
				}
			}).Start();
		}

		/// <summary>
		/// Processes the specified packet capture.
		/// </summary>
		/// <param name='capture'>
		/// The raw data captured from the interface.
		/// </param>
		public DataPacket Process(RawCapture capture)
		{
			var dpacket = new DataPacket();

			//Convert the raw data from the interface to a packet.
			var spacket = Packet.ParsePacket(capture.LinkLayerType, capture.Data);
			var ip = IpPacket.GetEncapsulated(spacket);

			/*
			 * Determine if the packet is a TCP packet.
			 * If it is map each of the fields of the packet to the
			 * new storage structure.
			 */
			var tcp = TcpPacket.GetEncapsulated(spacket);
			if (tcp != null && ip != null)
			{
				dpacket.IpAddressSource = ip.SourceAddress.ToString();
				dpacket.IpAddressDestination = ip.DestinationAddress.ToString();
				dpacket.PortSource = tcp.SourcePort;
				dpacket.PortDestination = tcp.DestinationPort;
				dpacket.Payload = tcp.PayloadData;
				dpacket.Protocol = NetworkProtocol.tcp;
				dpacket.Timestamp = DateTime.Now;

				//Notify the DNS worker thread that a new packet needs lookup.
				lock (DnsLookupQueue)
				{
					DnsLookupQueue.Enqueue(dpacket);
				}
				WaitHandle.Set();

				return dpacket;
			}

			/*
			 * Determine if the packet is an UDP packet.
			 * If it is map each of the fields of the packet to the
			 * new storage structure.
			 */
			var udp = UdpPacket.GetEncapsulated(spacket);
			if (udp != null && ip != null)
			{
				dpacket.IpAddressSource = ip.SourceAddress.ToString();
				dpacket.IpAddressDestination = ip.DestinationAddress.ToString();
				dpacket.PortSource = udp.SourcePort;
				dpacket.PortDestination = udp.DestinationPort;
				dpacket.Payload = udp.PayloadData;
				dpacket.Protocol = NetworkProtocol.udp;
				dpacket.Timestamp = DateTime.Now;

				//Notify the DNS worker thread that a new packet needs lookup.
				lock (DnsLookupQueue)
				{
					DnsLookupQueue.Enqueue(dpacket);
				}
				WaitHandle.Set();

				return dpacket;
			}

			/*
			 * Determine if the packet is an ICMP packet.
			 * If it is map each of the fields of the packet to the
			 * new storage structure.
			 */
			var icmp = ICMPv4Packet.GetEncapsulated(spacket);
			if (icmp != null && ip != null)
			{
				dpacket.IpAddressSource = ip.SourceAddress.ToString();
				dpacket.IpAddressDestination = ip.DestinationAddress.ToString();
				dpacket.Type = icmp.TypeCode.ToString();
				dpacket.Payload = icmp.PayloadData;
				dpacket.Protocol = NetworkProtocol.icmp;
				dpacket.Timestamp = DateTime.Now;

				//Notify the DNS worker thread that a new packet needs lookup.
				lock (DnsLookupQueue)
				{
					DnsLookupQueue.Enqueue(dpacket);
				}
				WaitHandle.Set();

				return dpacket;
			}

			/*
			 * Determine if the packet is an ARP packet.
			 * If it is map each of the fields of the packet to the
			 * new storage structure.
			 */
			var arp = ARPPacket.GetEncapsulated(spacket);
			if (arp != null)
			{
				dpacket.Timestamp = DateTime.Now;
				dpacket.HardwareAddressSource = arp.SenderHardwareAddress.ToString();
				dpacket.HardwareAddressTarget = arp.TargetHardwareAddress.ToString();
				dpacket.Protocol = NetworkProtocol.arp;
				dpacket.Payload = spacket.PayloadData;

				return dpacket;
			}

			//Console.WriteLine("  UNKNOWN TYPE: " + ((EthernetPacket)spacket).Type.ToString());
            return null;
		}
	}
}

