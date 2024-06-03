namespace TestApi.Services
{
    public interface IEmailSendService
    {
        Task<string>  SendEmailAsync(string toEmail, string subject, string message);
    }
}
