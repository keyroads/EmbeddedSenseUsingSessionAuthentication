using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(EmbeddedSenseUsingSessionAuthentication.Startup))]
namespace EmbeddedSenseUsingSessionAuthentication
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
