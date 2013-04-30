using System;
using System.Collections.Generic;

namespace WireSentry.SDK
{
	/// <summary>
	/// Scanner which is inherited by all handler modules which are to be loaded.
	/// </summary>
	public abstract class Handler
	{
		protected virtual IDebug Debugger { get; set; }

		/// <summary>
		/// Initializes a new instance of the <see cref="WireSentry.SDK.Handler"/> class.
		/// </summary>
		/// <param name='debugger'>
		/// Debugger.
		/// </param>
		public Handler(IDebug debugger)
		{
			Debugger = debugger;
		}

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
		/// Handle the specified results by performing some action.
		/// </summary>
		/// <param name='results'>
		/// The results of a scanner which detected activity.
		/// </param>
		public abstract void Handle(ScannerResult results);
	}
}

