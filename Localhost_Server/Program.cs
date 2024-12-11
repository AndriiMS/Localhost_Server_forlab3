using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

class Server
{
    static void Main()
    {
        RunServer();
    }

    static void RunServer()
    {
        Console.WriteLine("Сервер запускається...");
        try
        {
            // Завантаження серверного сертифіката
            var serverCertificate = new X509Certificate2("Certificates/ServerCertificate.pfx", "ThebestPassword", X509KeyStorageFlags.DefaultKeySet);

            TcpListener listener = new TcpListener(IPAddress.Loopback, 5000);
            listener.Start();
            Console.WriteLine("Сервер чекає на підключення...");

            while (true)
            {
                using var client = listener.AcceptTcpClient();
                using var sslStream = new SslStream(client.GetStream(), false, ValidateClientCertificate);

                sslStream.AuthenticateAsServer(serverCertificate, true, System.Security.Authentication.SslProtocols.Tls13, false);
                Console.WriteLine("Клієнт підключився.");

                // Отримання повідомлення
                byte[] buffer = new byte[2048];
                int bytesRead = sslStream.Read(buffer, 0, buffer.Length);
                string message = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                Console.WriteLine($"Отримано повідомлення: {message}");
            }
        }

        catch (Exception ex)
        {
            Console.WriteLine($"Помилка завантаження сертифіката сервера: {ex.Message}");
            return;
        }

    }

    static bool ValidateClientCertificate(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
    {
        if (certificate == null)
        {
            Console.WriteLine("Сертифікат клієнта відсутній.");
            return false;
        }

        if (sslPolicyErrors == SslPolicyErrors.None)
        {
            Console.WriteLine("Клієнтський сертифікат дійсний.");
            return true;
        }

        Console.WriteLine($"Помилки сертифіката: {sslPolicyErrors}");
        return false;
    }
}