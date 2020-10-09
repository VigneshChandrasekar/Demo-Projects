using Owin;
using Sitecore.Diagnostics;
using Sitecore.Owin.Authentication.Configuration;
using Sitecore.Owin.Authentication.Pipelines.IdentityProviders;
using Sitecore.Owin.Authentication.Services;
using System.Globalization;
using System.Threading.Tasks;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OpenIdConnect;
using Microsoft.Owin.Infrastructure;
using Sitecore.Abstractions;

namespace Demo.Foundation.Accounts.Infrastructure.Pipelines.IdentityProviders
{
    public class AzureADIdentityProvider : IdentityProvidersProcessor
    {
        public AzureADIdentityProvider(
            FederatedAuthenticationConfiguration federatedAuthenticationConfiguration, 
            ICookieManager cookieManager, 
            BaseSettings baseSettings) 
            : base(federatedAuthenticationConfiguration, cookieManager, baseSettings)
        {

        }
        protected override string IdentityProviderName
        {
            get { return Settings.GetSetting("azureAD:IdentityProviderName"); }
        }
        protected override void ProcessCore(IdentityProvidersArgs args)
        {
            Assert.ArgumentNotNull(args, nameof(args));

            var identityProvider = this.GetIdentityProvider();
            var authenticationType = this.GetAuthenticationType();

            string azureADInstance = Settings.GetSetting("azureAD:Instance");
            string tenant = Settings.GetSetting("azureAD:Tenant");
            string clientId = Settings.GetSetting("azureAD:ClientId");
            string postLogoutRedirectUri = Settings.GetSetting("azureAD:PostLogoutRedirectUri");
            string redirectUri = Settings.GetSetting("azureAD:RedirectUri");

            string authority = string.Format(CultureInfo.InvariantCulture, azureADInstance, tenant);

            args.App.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                Caption = identityProvider.Caption,
                AuthenticationType = authenticationType,
                AuthenticationMode = AuthenticationMode.Passive,
                ClientId = clientId,
                Authority = authority,
                PostLogoutRedirectUri = postLogoutRedirectUri,
                RedirectUri = redirectUri,

                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    SecurityTokenValidated = notification =>
                    {
                        var identity = notification.AuthenticationTicket.Identity;

                        foreach (var claimTransformationService in identityProvider.Transformations)
                        {
                            claimTransformationService.Transform(identity,
                                new TransformationContext(FederatedAuthenticationConfiguration, identityProvider));
                        }

                        notification.AuthenticationTicket = new AuthenticationTicket(identity, notification.AuthenticationTicket.Properties);

                        return Task.FromResult(0);
                    }

                }
            });
        }

    }
}