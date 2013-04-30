using System;

namespace WireSentry.SDK
{
	/// <summary>
	/// Redirects debug output to the appropriate destination.
	/// </summary>
	public interface IDebug
	{
		void Out(int level, string message);
		void Out(int level, string message, ConsoleColor color);
		void Out(int level, string message, ConsoleColor color, params object[] args);
		void Put(int level, string message);
		void Put(int level, string message, ConsoleColor color);
		void Put(int level, string message, ConsoleColor color, params object[] args);

		void Status(string message);
		void Failure(string message);
		void Failure(Exception e);
		void Failure();
		void Success();
	}
}