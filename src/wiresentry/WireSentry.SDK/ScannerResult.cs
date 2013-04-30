using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace WireSentry.SDK
{
	/// <summary>
	/// Represents the results of a particular Scanner's scan.
	/// </summary>
	public class ScannerResult
	{
		public string AttackAddress { get; protected set; }
		public string VictimAddress { get; protected set; }
		public string AttackType { get; protected set; }
		public string Signature { get; protected set; }
		public Scanner Scanner { get; protected set; }
		public IEnumerable<DataPacket> Packets { get; protected set; }

		/// <summary>
		/// Initializes a new instance of the <see cref="WireSentry.SDK.ScannerResult"/> class.
		/// </summary>
		/// <param name='attackerAddress'>
		/// Attacker's IP address.
		/// </param>
		/// <param name='victimAddress'>
		/// Victim's IP address.
		/// </param>
		/// <param name='attackType'>
		/// The type of attack that occurred.
		/// </param>
		/// <param name='scanner'>
		/// The scanner that detected the attack.
		/// </param>
		/// <param name='packets'>
		/// The collection of packets associated with the attack.
		/// </param>
		public ScannerResult(string attackerAddress, 
		                     string victimAddress, 
		                     string attackType, 
		                     Scanner scanner, 
		                     IEnumerable<DataPacket> packets)
		{
			AttackAddress = attackerAddress;
			VictimAddress = victimAddress;
			AttackType = attackType;
			Scanner = scanner;
			Packets = packets;

			//Calculate an unique signature for the attack.
			Signature = CalculateSignature();
		}

		/// <summary>
		/// Adds packets to the attack (for ongoing attacks).
		/// </summary>
		/// <param name='packets'>
		/// The collection of packets to add to the attack.
		/// </param>
		public void AddPackets(IEnumerable<DataPacket> packets)
		{
			Packets = Packets.Union(packets);
		}

		/// <summary>
		/// Calculates an unique signature for the attack.
		/// </summary>
		/// <returns>
		/// The unique attack signature.
		/// </returns>
		protected virtual string CalculateSignature()
		{
			//Use these variables as input that make the attack unique.
			var input = Scanner.Id + AttackAddress + VictimAddress + AttackType;

			//Calculate a MD5 hash of the unique input.
			var builder = new StringBuilder();
			var bytes = Encoding.ASCII.GetBytes(input);
			var hash = new MD5CryptoServiceProvider().ComputeHash(bytes);
			for (int i = 0; i < hash.Length; i++)
			{
				builder.Append(hash[i].ToString("X2"));
			}

			return builder.ToString();
		}

		/// <summary>
		/// Returns a <see cref="System.String"/> that represents the current <see cref="WireSentry.SDK.ScannerResult"/>.
		/// </summary>
		/// <returns>
		/// A <see cref="System.String"/> that represents the current <see cref="WireSentry.SDK.ScannerResult"/>.
		/// </returns>
		public override string ToString()
		{
			return string.Format("\tscanner: '{0}' attack {1} -> {2} ({3} packets)",
			                     AttackType,
			                     AttackAddress,
			                     VictimAddress,
			                     Packets.Count());
		}
	}
}