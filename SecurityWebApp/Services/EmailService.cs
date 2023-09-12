using Mailjet.Client;
using Mailjet.Client.TransactionalEmails;
using Microsoft.Extensions.Configuration;
using SecurityWebApp.Dtos;
using System.Threading.Tasks;

namespace SecurityWebApp.Services;
public class EmailService
{
    private readonly IConfiguration _config;

    public EmailService(IConfiguration config)
    {
        _config = config;
    }

    public async Task<bool> SendEmailAsync(EmailSendDto emailSendDto)
    {
        MailjetClient client = new MailjetClient(_config["MailJet:ApiKey"], _config["MailJet:SecretKey"]);

        var email = new TransactionalEmailBuilder()
                .WithFrom(new SendContact(_config["Email:From"], _config["Email:ApplicationName"]))
                .WithSubject(emailSendDto.Subject)
                .WithHtmlPart(emailSendDto.Body)
                .WithTo(new SendContact(emailSendDto.To))
                .Build();

        var response = await client.SendTransactionalEmailAsync(email);
        if(response.Messages != null)
        {
            if (response.Messages[0].Status == "success")
            {
                return true;
            }
        }
        return false;
    }
}
