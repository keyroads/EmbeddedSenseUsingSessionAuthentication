using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Web;

namespace EmbeddedSenseUsingSessionAuthentication.Controllers
{
    public class SenseAuthModule
    {
        private const string RESTURI = "https://zyg-sp4:4243/qps/portal/";
        private const string QlikSessionKey = "X-Qlik-Portal-Session";

        private static string GenerateXrfkey()
        {
            var chars = "abcdefghijklmnopqrstuwxyzABCDEFGHIJKLMNOPQRSTUWXYZ0123456789";
            var rvalue = "";
            var clen = chars.Length;
            var randomBytes = new byte[16];
            var crypto = new RNGCryptoServiceProvider();
            crypto.GetBytes(randomBytes);

            for (var i = 0; i < 16; i++) { rvalue = rvalue + chars[randomBytes[i] % clen]; }

            return rvalue;
        }

        private static bool CheckValidationResult(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) { return true; }

        private static WebRequestHandler CreateWebRequestHandler()
        {
            var handler = new WebRequestHandler();
            handler.ClientCertificateOptions = ClientCertificateOption.Manual;
            handler.ClientCertificates.Add(new X509Certificate2(@"C:\Users\heave\Documents\client.pfx", "kr",
                    X509KeyStorageFlags.MachineKeySet));
            handler.ServerCertificateValidationCallback += CheckValidationResult;
            handler.UseProxy = false;
            return handler;
        }

        private static HttpClient CreateSenseHttpClient(string xrfKey, string proxyRestUri = RESTURI)
        {
            var restClient = new HttpClient(CreateWebRequestHandler());
            restClient.BaseAddress = new Uri(proxyRestUri);
            restClient.DefaultRequestHeaders.Accept.Clear();
            restClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            restClient.DefaultRequestHeaders.Add("X-Qlik-Xrfkey", xrfKey);
            return restClient;
        }

        public static async Task CreateSession(HttpContextBase httpContext)
        {
            // 生成xrfKey
            var xrfKey = GenerateXrfkey();

            // 生成提交数据 Json格式
            var reqObject = new Hashtable();
            reqObject.Add("UserId", "heave");
            reqObject.Add("UserDirectory", "ZYG-SP4");
            reqObject.Add("SessionId", Guid.NewGuid().ToString());

            var restClient = CreateSenseHttpClient(xrfKey);

            var response = await restClient.PostAsJsonAsync($"session?Xrfkey={xrfKey}", reqObject);
            if (response.IsSuccessStatusCode)
            {
                var result = await response.Content.ReadAsAsync<Hashtable>();
                httpContext.Response.SetCookie(new HttpCookie(QlikSessionKey, result["SessionId"].ToString()));
            }
            else
                throw new Exception($"访问Qlik Sense服务器地址：{RESTURI} 返回错误代码：{response.StatusCode}");
        }

        public static async Task DeleteSession(HttpContextBase httpContext)
        {
            var sessionId = httpContext.Session[QlikSessionKey]?.ToString();
            if (string.IsNullOrEmpty(sessionId)) return;

            // 生成xrfKey
            var xrfKey = GenerateXrfkey();

            var restClient = CreateSenseHttpClient(xrfKey);

            var response = await restClient.DeleteAsync($"session/{sessionId}?Xrfkey={xrfKey}");
            if (response.IsSuccessStatusCode)
            {
                httpContext.Response.Cookies.Remove(QlikSessionKey);
            }
            else
                throw new Exception($"访问Qlik Sense服务器地址：{RESTURI} 返回错误代码：{response.StatusCode}");

        }

        public static async Task<string> AddTicket(string targetId, string proxyRestUri)
        {
            if (string.IsNullOrEmpty(targetId)) throw new Exception($"{nameof(targetId)} is empty");
            if (string.IsNullOrEmpty(proxyRestUri)) throw new Exception($"{nameof(proxyRestUri)} is empty");
            
            // 生成xrfKey
            var xrfKey = GenerateXrfkey();

            // 生成提交数据 Json格式
            var reqObject = new Hashtable();
            reqObject.Add("UserId", "heave");
            reqObject.Add("UserDirectory", "ZYG-SP4");
            reqObject.Add("TargetId", targetId);

            var restClient = CreateSenseHttpClient(xrfKey, proxyRestUri);

            var response = await restClient.PostAsJsonAsync($"ticket?Xrfkey={xrfKey}", reqObject);
            if (response.IsSuccessStatusCode)
            {
                var result = await response.Content.ReadAsAsync<Hashtable>();
                var ticket = result["Ticket"].ToString();
                var targetUri = result["TargetUri"].ToString();

                if (string.IsNullOrEmpty(targetUri))
                    throw new Exception(nameof(targetUri) + " is empty");

                //Add ticket to TargetUri
                string redirectUrl;
                if (targetUri.Contains("?"))
                    redirectUrl = targetUri + "&qlikTicket=" + ticket;
                else
                    redirectUrl = targetUri + "?qlikTicket=" + ticket;

                return redirectUrl;
            }
            else
                throw new Exception($"访问Qlik Sense服务器地址：{RESTURI} 返回错误代码：{response.StatusCode}");

        }
    }
}