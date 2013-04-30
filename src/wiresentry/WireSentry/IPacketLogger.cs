using System;
using System.Collections.Generic;
using WireSentry.SDK;

namespace WireSentry
{
	public interface IPacketLogger
	{
		/// <summary>
		/// Opens a connection to the destination device.
		/// </summary>
		void Open();

		/// <summary>
		/// Closes a connection to the destination device.
		/// </summary>
		void Close();

		/// <summary>
		/// Creates a new event in the log.
		/// </summary>
		/// <param name='result'>
		/// The result of the scanner.
		/// </param>
		void Create(ScannerResult result);

		/// <summary>
		/// Updates an existing event in the log.
		/// </summary>
		/// <param name='result'>
		/// Result.
		/// </param>
		void Update(ScannerResult result);
	}
}

