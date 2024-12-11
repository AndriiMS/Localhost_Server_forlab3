using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;

class Server
{
    static void Main()
    {
        RunServer();
    }

    static void RunServer()
    {
        Console.OutputEncoding = Encoding.UTF8;
        Console.WriteLine("Сервер запускається...");

        try
        {
            // Завантаження серверного сертифіката
            var serverCertificate = new X509Certificate2("Certificates/ServerCertificate.pfx", "ThebestPassword", X509KeyStorageFlags.DefaultKeySet);

            TcpListener listener = new TcpListener(IPAddress.Loopback, 5000);
            listener.Start();
            Console.WriteLine("Сервер чекає на підключення...");
            if (!File.Exists("Certificates/ServerCertificate.pfx"))
            {
                Console.WriteLine("Файл серверного сертифіката не знайдено.");
            }
            while (true)
            {
                using var client = listener.AcceptTcpClient();
                Console.WriteLine("Новий клієнт підключився.");

                using var sslStream = new SslStream(client.GetStream(), false, ValidateClientCertificate);

                try
                {
                    sslStream.AuthenticateAsServer(serverCertificate, true, System.Security.Authentication.SslProtocols.Tls12, false);
                    Console.WriteLine("SSL-з'єднання встановлено.");

                    // Отримання повідомлення
                    byte[] buffer = new byte[2048];
                    int bytesRead = sslStream.Read(buffer, 0, buffer.Length);
                    string message = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                    Console.WriteLine($"Отримано повідомлення: {message}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Помилка аутентифікації: {ex.Message}");
                    if (ex.InnerException != null)
                    {
                        Console.WriteLine($"Деталі: {ex.InnerException.Message}");
                    }

                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Помилка: {ex.Message}");
        }
    }

    static bool ValidateClientCertificate(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
    {
        Console.WriteLine("Перевірка клієнтського сертифіката...");

        if (certificate == null)
        {
            Console.WriteLine("Сертифікат клієнта відсутній.");
            return false;
        }

        Console.WriteLine($"Сертифікат клієнта: {certificate.Subject}");

        if (sslPolicyErrors == SslPolicyErrors.None)
        {
            Console.WriteLine("Клієнтський сертифікат дійсний.");
            return true;
        }

        Console.WriteLine($"Помилки сертифіката: {sslPolicyErrors}");
        if (chain != null)
        {
            foreach (var status in chain.ChainStatus)
            {
                Console.WriteLine($"Статус: {status.StatusInformation}");
            }
        }

        return false;
    }
}