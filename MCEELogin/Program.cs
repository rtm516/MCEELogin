using System;
using System.Net;
using System.Threading.Tasks;
using Titanium.Web.Proxy;
using Titanium.Web.Proxy.EventArguments;
using Titanium.Web.Proxy.Models;

namespace MCEELogin
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Starting proxy...");

            ProxyServer proxyServer = new ProxyServer();

            // Generate a cert if needed
            if (proxyServer.CertificateManager.RootCertificate == null)
            {
                proxyServer.CertificateManager.CreateRootCertificate();
            }

            // Trust the root cert if needed
            if (!proxyServer.CertificateManager.IsRootCertificateMachineTrusted())
            {
                proxyServer.CertificateManager.TrustRootCertificateAsAdmin(true);
            }

            proxyServer.BeforeRequest += OnRequest;
            proxyServer.BeforeResponse += OnResponse;
            proxyServer.ServerCertificateValidationCallback += OnCertificateValidation;
            proxyServer.ClientCertificateSelectionCallback += OnCertificateSelection;

            var explicitEndPoint = new ExplicitProxyEndPoint(IPAddress.Loopback, 1337, true);
            explicitEndPoint.BeforeTunnelConnectRequest += OnBeforeTunnelConnectRequest;
            proxyServer.AddEndPoint(explicitEndPoint);

            proxyServer.Start();

            // Set as the system proxy
            proxyServer.SetAsSystemHttpProxy(explicitEndPoint);
            proxyServer.SetAsSystemHttpsProxy(explicitEndPoint);

            Console.WriteLine("Proxy ready!");

            // Wait here
            Console.ReadLine();

            // Unsubscribe & Quit
            explicitEndPoint.BeforeTunnelConnectRequest -= OnBeforeTunnelConnectRequest;
            proxyServer.BeforeRequest -= OnRequest;
            proxyServer.BeforeResponse -= OnResponse;
            proxyServer.ServerCertificateValidationCallback -= OnCertificateValidation;
            proxyServer.ClientCertificateSelectionCallback -= OnCertificateSelection;

            proxyServer.Stop();
        }

        private static async Task OnBeforeTunnelConnectRequest(object sender, TunnelConnectSessionEventArgs e)
        {
            string hostname = e.HttpClient.Request.RequestUri.Host;

            // Disable ssl decryption for anything we don't care about
            if (!hostname.Equals("login.microsoftonline.com") && !hostname.Equals("login.windows.net"))
            {
                e.DecryptSsl = false;
            }
        }

        public static async Task OnRequest(object sender, SessionEventArgs e)
        {
            // Patch the request to login
            if (e.HttpClient.Request.Host.Equals("login.microsoftonline.com"))
            {
                e.HttpClient.Request.Url = e.HttpClient.Request.Url.Replace("redirect_uri=urn%3aietf%3awg%3aoauth%3a2.0%3aoob", "redirect_uri=https%3a%2f%2flogin.microsoftonline.com%2fcommon%2foauth2%2fnativeclient");
                Console.WriteLine("Patched login.microsoftonline.com request");
            }

            // Patch the token request post login
            if (e.HttpClient.Request.Host.Equals("login.windows.net") && e.HttpClient.Request.HasBody)
            {
                string body = await e.GetRequestBodyAsString();
                e.SetRequestBodyString(body.Replace("redirect_uri=urn%3aietf%3awg%3aoauth%3a2.0%3aoob", "redirect_uri=https%3a%2f%2flogin.microsoftonline.com%2fcommon%2foauth2%2fnativeclient"));
                Console.WriteLine("Patched login.windows.net request");
            }
        }

        public static async Task OnResponse(object sender, SessionEventArgs e)
        {
            // Patch the redirect uri
            if (e.HttpClient.Request.RequestUriString.StartsWith("https://login.microsoftonline.com/common/oauth2/nativeclient"))
            {
                e.HttpClient.Response.ContentType = "text/html";
                e.SetResponseBodyString("<script>document.location.replace(\"" + e.HttpClient.Request.RequestUriString.Replace("https://login.microsoftonline.com/", "urn:ietf:wg:oauth:2.0:oob") + "\")</script>");
                Console.WriteLine("Patched callback response");
            }
        }

        #region Cert stuff from example
        // Allows overriding default certificate validation logic
        public static Task OnCertificateValidation(object sender, CertificateValidationEventArgs e)
        {
            // set IsValid to true/false based on Certificate Errors
            if (e.SslPolicyErrors == System.Net.Security.SslPolicyErrors.None)
                e.IsValid = true;

            return Task.CompletedTask;
        }

        // Allows overriding default client certificate selection logic during mutual authentication
        public static Task OnCertificateSelection(object sender, CertificateSelectionEventArgs e)
        {
            // set e.clientCertificate to override
            return Task.CompletedTask;
        }
        #endregion
    }
}
