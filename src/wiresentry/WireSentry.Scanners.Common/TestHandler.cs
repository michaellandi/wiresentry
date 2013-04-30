using System;
using WireSentry.SDK;
using System.Net.Mail;

namespace WireSentry.Scanners.Common
{
	public class TestHandler : Handler
	{
		public TestHandler(IDebug debugger) : base(debugger)
		{

		}

		#region implemented abstract members of Handler

		public override void Handle(ScannerResult results)
		{
			var message = new MailMessage();
			message.To.Add("mlandi@sourcesecure");
			message.From = new MailAddress("info@wiresentry.com");
			message.Subject = results.AttackType + " Attack Detected!";
			message.Body = results.AttackAddress + " -> " + results.VictimAddress;
			message.Priority = MailPriority.High;

			new SmtpClient("mail.optonline.net", 25).Send(message);
		}

		public override Guid Id
		{
			get
			{
				return new Guid("e61374e6-4525-47ca-9fb8-0aa4313c7671");
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
				return "Test Handler";
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

