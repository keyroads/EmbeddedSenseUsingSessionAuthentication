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
    public class SenseSessionModule
    {
        private const string RESTURI = "https://zyg-sp4:4243/qps/";

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

        public static async Task CreateSession(HttpContextBase httpContext)
        {
            // 生成xrfKey
            var xrfKey = GenerateXrfkey();

            // 生成提交数据 Json格式
            var reqObject = new Hashtable();
            reqObject.Add("UserId", "heave");
            reqObject.Add("UserDirectory", "ZYG-SP4");
            reqObject.Add("SessionId", Guid.NewGuid().ToString());

            var handler = new WebRequestHandler();
            handler.ClientCertificateOptions = ClientCertificateOption.Manual;
            handler.ClientCertificates.Add(new X509Certificate2(@"C:\Users\heave\Documents\client.pfx", "kr",
                    X509KeyStorageFlags.MachineKeySet));
            handler.ServerCertificateValidationCallback += CheckValidationResult;
            handler.UseProxy = false;

            var restClient = new HttpClient(handler);
            restClient.BaseAddress = new Uri(RESTURI);
            restClient.DefaultRequestHeaders.Accept.Clear();
            restClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            restClient.DefaultRequestHeaders.Add("X-Qlik-Xrfkey", xrfKey);

            var response = await restClient.PostAsJsonAsync($"session?Xrfkey={xrfKey}", reqObject);
            if (response.IsSuccessStatusCode)
            {
                var result = await response.Content.ReadAsAsync<Hashtable>();
                httpContext.Response.SetCookie(new HttpCookie("X-Qlik-Session", result["SessionId"].ToString()));
            }
            else
                throw new Exception($"访问Qlik Sense服务器地址：{RESTURI} 返回错误代码：{response.StatusCode}");
        }

        public static async Task DeleteSession(HttpContextBase httpContext)
        {
            var sessionId = httpContext.Session["X-Qlik-Session"]?.ToString();
            if (string.IsNullOrEmpty(sessionId)) return;

            // 生成xrfKey
            var xrfKey = GenerateXrfkey();

            var handler = new WebRequestHandler();
            handler.ClientCertificateOptions = ClientCertificateOption.Manual;
            handler.ClientCertificates.Add(new X509Certificate2(@"C:\Users\heave\Documents\client.pfx", "kr",
                    X509KeyStorageFlags.MachineKeySet));
            handler.ServerCertificateValidationCallback += CheckValidationResult;
            handler.UseProxy = false;

            var restClient = new HttpClient(handler);
            restClient.BaseAddress = new Uri(RESTURI);
            restClient.DefaultRequestHeaders.Accept.Clear();
            restClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            restClient.DefaultRequestHeaders.Add("X-Qlik-Xrfkey", xrfKey);

            var response = await restClient.DeleteAsync($"session/{sessionId}?Xrfkey={xrfKey}");
            if (response.IsSuccessStatusCode)
            {
                httpContext.Response.Cookies.Remove("X-Qlik-Session");
            }
            else
                throw new Exception($"访问Qlik Sense服务器地址：{RESTURI} 返回错误代码：{response.StatusCode}");

        }
    }
}