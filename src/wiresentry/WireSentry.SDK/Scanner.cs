using System;
using System.Collections.Generic;

namespace WireSentry.SDK
{
	/// <summary>
	/// Scanner which is inherited by all scanner modules which are to be loaded.
	/// </summary>
	public abstract class Scanner
	{
		protected virtual IDebug Debugger { get; set; }

		/// <summary>
		/// Initializes a new instance of the <see cref="WireSentry.SDK.Scanner"/> class.
		/// </summary>
		/// <param name='debugger'>
		/// The debugger instance to use for debug output.
		/// </param>
		public Scanner(IDebug debugger)
		{
			Debugger = debugger;
		}

		/// <summary>
		/// Gets the frequency that the scanner should execute in seconds.
		/// </summary>
		/// <value>
		/// The frequency that the scanner should run in seconds.
		/// </value>
		public abstract int Frequency { get; }

		/// <summary>
		/// Gets the unique identifier of this scanner.
		/// </summary>
		/// <value>
		/// The unique identifier of the scanner.
		/// </value>
		public abstract Guid Id { get; }

		/// <summary>
		/// Gets the author of the scanner.
		/// </summary>
		/// <value>
		/// The author of the scanner.
		/// </value>
		public abstract string Author { get; } 

		/// <summary>
		/// Gets the name of the scanner.
		/// </summary>
		/// <value>
		/// The name of the scanner.
		/// </value>
		public abstract string Name { get; }

		/// <summary>
		/// Gets the version of the scanner.
		/// </summary>
		/// <value>
		/// The version of the scanner.
		/// </value>
		public abstract string Version { get; }

		/// <summary>
		/// Scans the specified packets for patterns.
		/// </summary>
		/// <param name='packets'>
		/// The collection of packets to scan.
		/// </param>
		public abstract IEnumerable<ScannerResult> Scan(IDataPacketCollection packets);
	}
}