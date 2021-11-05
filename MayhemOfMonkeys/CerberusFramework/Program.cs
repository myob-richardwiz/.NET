using Microsoft.Identity.Client;
using Nito.AsyncEx;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CerberusFramework
{
    class Program
    {
        static void Main(string[] args)
        {
	        //ConfidentialClientApplicationOptions options = GetOptions(); // your own method
            /*IConfidentialClientApplication app = ConfidentialClientApplicationBuilder.CreateWithApplicationOptions(options)
				.Build();*/
            /*IConfidentialClientApplication app = ConfidentialClientApplicationBuilder.Create("6b9cb2d1-6e79-40e2-a8c5-57c50a75dfa9")
		            .Build();*/
            IPublicClientApplication app = PublicClientApplicationBuilder.Create("6b9cb2d1-6e79-40e2-a8c5-57c50a75dfa9")
				.WithAuthority(AzureCloudInstance.AzurePublic, "a4bedeb1-28ad-43ba-8557-f533ac27ac8a", true)
				.WithRedirectUri("https://localhost:44368/")
                    .Build();
            AuthenticationResult result = GetIdToken(app).Result;
            //AuthenticationResult result = await oauth.AcquireTokenAsync(new[] { "...scopes..." }, deviceCodeCallback =>
            //                                                            {
            //                                                             // Prints message instructing user to go to https://microsoft.com/devicelogin and enter device code
            //                                                             Console.WriteLine(deviceCodeCallback.Message);
            //                                                             return Task.FromResult(0);
            //                                                            });
            Console.WriteLine(GetTokenInfo(result));
            Console.ReadLine();
        }

        private static async Task<AuthenticationResult> GetIdToken(IPublicClientApplication app)
        {
	        AuthenticationResult authResult = null;
	        string resultText = string.Empty;
	        string tokeninfo = String.Empty;
	        //Set the scope for API call to
	        string[] scopes = new string[] { "openid","profile" };
	        try
	        {
		        authResult = await app.AcquireTokenInteractive(scopes)
		                              //.WithAccount(accounts.FirstOrDefault())
		                              .WithPrompt(Prompt.SelectAccount)
		                              .ExecuteAsync();
	        }
	        catch (MsalException msalex)
	        {
		        resultText = $"Error Acquiring Token:{System.Environment.NewLine}{msalex}";
	        }

	        if (authResult != null)
	        {
		        tokeninfo = authResult.IdToken;
		        // Use the token
	        }
	        string authHeader = authResult.CreateAuthorizationHeader();
	        string accessToken = authResult.AccessToken;
			return authResult;
        }

        private static string GetTokenInfo(AuthenticationResult authResult)
        {
	        string tokenInfo = String.Empty;
	        if (authResult != null)
	        {
		        tokenInfo += $"Username: {authResult.Account.Username}" + Environment.NewLine;
		        tokenInfo += $"Token Expires: {authResult.ExpiresOn.ToLocalTime()}" + Environment.NewLine;
	        }

	        return tokenInfo;
        }
    }
}
