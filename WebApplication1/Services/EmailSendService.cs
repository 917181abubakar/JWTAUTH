using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using MimeKit;
using MimeKit.Text;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;
using TestApi.Services;

public class EmailSendService : IEmailSendService
{

    private readonly SmtpSettings _smtpSettings;
    private readonly ILogger<EmailSendService> _logger;

    public EmailSendService(IConfiguration configuration, ILogger<EmailSendService> logger)
    {
        _smtpSettings = configuration.GetSection("Email").Get<SmtpSettings>();
        _logger = logger;
    }

    public async Task<string> SendEmailAsync(string toEmail, string subject, string message)
    {
        var email = new MailMessage
        {
            From = new MailAddress(_smtpSettings.FromEmail),
            Subject = subject,
            Body = message,
            IsBodyHtml = false // Set to true if the message contains HTML
        };
        email.To.Add(new MailAddress(toEmail));

        //email.From.Add(MailboxAddress.Parse(_smtpSettings.FromEmail));
        //email.To.Add(MailboxAddress.Parse(_smtpSettings.FromEmail));
        //email.Subject=subject;
        //email.Body=new TextPart(TextFormat.Plain) { Text=message};
        using (var smtp = new SmtpClient())
        {
            smtp.Port = _smtpSettings.port;
            smtp.EnableSsl = true;
            smtp.Host = _smtpSettings.server;
            smtp.Credentials = new NetworkCredential(userName: _smtpSettings.username, password: _smtpSettings.password);
            await smtp.SendMailAsync(email);
            return ("Email sent successfully.");
        }
    }
}

public class SmtpSettings
{
    public string server { get; set; }
    public int port { get; set; }
    public string username { get; set; }
    public string password { get; set; }
    public string FromEmail { get; set; }
}
