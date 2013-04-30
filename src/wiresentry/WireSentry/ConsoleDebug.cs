using System;
using WireSentry.SDK;

namespace WireSentry
{
	/// <summary>
	/// Redirects debug output to the Console.
	/// </summary>
	public class ConsoleDebug : IDebug
	{
		public int Verbosity { get; protected set; }

		public ConsoleDebug(int verbosity)
		{
			Verbosity = verbosity;
		}

		public void Out(int level, string message)
		{
			message = message.Replace("\t", "     ");

			if (level <= Verbosity)
			{
				Console.Write(message);
			}
		}

		public void Out(int level, string message, ConsoleColor color)
		{
			message = message.Replace("\t", "     ");

			if (level <= Verbosity)
			{
				ConsoleColor defaultColor = Console.ForegroundColor;
				Console.ForegroundColor = color;
				Console.Write(message);
				Console.ForegroundColor = defaultColor;
			}
		}

		public void Out(int level, string message, ConsoleColor color, params object[] args)
		{
			message = message.Replace("\t", "     ");

			Out(level, string.Format(message, args), color);
		}

		public void Put(int level, string message)
		{
			message = message.Replace("\t", "     ");

			Out(level, message + Environment.NewLine);
		}

		public void Put(int level, string message, ConsoleColor color)
		{
			message = message.Replace("\t", "     ");

			Out(level, message + Environment.NewLine, color);
		}

		public void Put(int level, string message, ConsoleColor color, params object[] args)
		{
			message = message.Replace("\t", "     ");
			
			Out(level, message + Environment.NewLine, color, args);
		}

		public void Status(string message)
		{
			message = message.Replace("\t", "     ");

			Console.Write(message);

			if (message.Length < Console.WindowWidth + 7)
			{
				for (int i = 0; i < (Console.WindowWidth - (message.Length + 7)); i++)
				{
					Console.Write(" ");
				}
			} 
			else
			{
				var leftover = message.Length + 7 % Console.WindowWidth;

				for (int i = 0; i < leftover - 7; i++)
				{
					Console.Write(" ");
				}
			}
		}

		public void Failure()
		{
			ConsoleColor defaultColor = Console.ForegroundColor;
			Console.Write(" [");
			Console.ForegroundColor = ConsoleColor.Red;
			Console.Write("FAIL");
			Console.ForegroundColor = defaultColor;
			Console.WriteLine("]");
		}

		public void Failure(string message)
		{
			message = message.Replace("\t", "     ");

			Failure();

			ConsoleColor defaultColor = Console.ForegroundColor;
			Console.ForegroundColor = ConsoleColor.Red;
			Console.WriteLine(message);
			Console.ForegroundColor = defaultColor;
		}

		public void Failure(Exception e)
		{
			Failure(e.Message);
		}

		public void Success()
		{
			ConsoleColor defaultColor = Console.ForegroundColor;
			Console.Write(" [");
			Console.ForegroundColor = ConsoleColor.Green;
			Console.Write(" OK ");
			Console.ForegroundColor = defaultColor;
			Console.WriteLine("]");
		}
	}
}

