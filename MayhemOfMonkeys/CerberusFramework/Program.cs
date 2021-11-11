using Microsoft.Identity.Client;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

namespace CerberusFramework
{
    class Program
    {
		// The Client ID is used by the application to uniquely identify itself to Azure AD.
		static string _clientId = System.Configuration.ConfigurationManager.AppSettings["ClientId"];

		// RedirectUri is the URL where the user will be redirected to after they sign in.
		static string _redirectUri = System.Configuration.ConfigurationManager.AppSettings["RedirectUri"];

	    // Tenant is the tenant ID (e.g. contoso.onmicrosoft.com, or 'common' for multi-tenant)
	    static string _tenant = System.Configuration.ConfigurationManager.AppSettings["Tenant"];
	    
	    // Scopes are the security setings that tell what your are allowed to do with the Application
	    static string _scopes = System.Configuration.ConfigurationManager.AppSettings["Scopes"];

	    // Authority is the URL for authority, composed by Microsoft identity platform endpoint and the tenant name (e.g. https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0)
	    static string _authority = String.Format(System.Globalization.CultureInfo.InvariantCulture, System.Configuration.ConfigurationManager.AppSettings["Authority"], _tenant);
	    
	    // The GUID that indicates that the user is a consumer user from a Microsoft account is 9188040d-6c67-4c5b-b112-36a304b66dad
	    static string _azureIssuerId = String.Format(System.Globalization.CultureInfo.InvariantCulture, System.Configuration.ConfigurationManager.AppSettings["AzureIssuerId"], _tenant);

        static void Main(string[] args)
        {
            // MYOB
            IPublicClientApplication myobApp = PublicClientApplicationBuilder.Create("152afa0c-8bf5-4f1e-b125-38abe7bfb553")
                                                                         .WithAuthority(AzureCloudInstance.AzurePublic, "ec47f5ff-c7b8-4848-8659-11c2c424d120", true)
                                                                         .WithRedirectUri(_redirectUri)
                                                                         .Build();
            // Wiz
            IPublicClientApplication wizApp = PublicClientApplicationBuilder.Create(_clientId)
                                                                         .WithAuthority(AzureCloudInstance.AzurePublic, _tenant, true)
                                                                         .WithRedirectUri(_redirectUri)
                                                                         .Build();
			AuthenticationResult result = GetIdToken(wizApp).Result;
            
            if (result != null)
            {
	            Console.WriteLine(IsValidToken(result) ? GetTokenInfo(result) : "Token Invalid");
            }
            else
            {
	            Console.WriteLine("Could not retrieve Token Info");
            }
            Console.ReadLine();
        }

        private static async Task<AuthenticationResult> GetIdToken(IPublicClientApplication app)
        {
	        AuthenticationResult authResult = default(AuthenticationResult);
	        string resultText = string.Empty;

	        var accounts = await app.GetAccountsAsync();
	        var firstAccount = accounts.ToList().FirstOrDefault();
	        string[] scopes = _scopes.Split(','); 

	        try
	        {
		        authResult = await app.AcquireTokenInteractive(scopes).WithAccount(firstAccount)
		                              .WithPrompt(Prompt.SelectAccount).ExecuteAsync();
	        }
	        catch (MsalException msalex)
	        {
		        string res = $"Error Acquiring Token:{System.Environment.NewLine}{msalex}";
	        }

	        return authResult;
        }

        private static Boolean IsValidToken( AuthenticationResult authResult)
        {
	        string issuer = authResult.ClaimsPrincipal.Claims.FirstOrDefault(c => c.Type == "iss")?.Value;;//9188040d-6c67-4c5b-b112-36a304b66dad microsoft
	        string audience = authResult.ClaimsPrincipal.Claims.FirstOrDefault(c => c.Type == "aud")?.Value;//aud -6b9cb2d1-6e79-40e2-a8c5-57c50a75dfa9 _clientId
	        string expiry = authResult.ClaimsPrincipal.Claims.FirstOrDefault(c => c.Type == "exp")?.Value;//exp--1636577943 - timestamp
	        string preferredUserName = authResult.ClaimsPrincipal.Claims.FirstOrDefault(c => c.Type == "preferred_username")?.Value;//user logon richardwiz@outlook.com
	        string tenantId = authResult.ClaimsPrincipal.Claims.FirstOrDefault(c => c.Type == "tid")?.Value;//-a4bedeb1-28ad-43ba-8557-f533ac27ac8a

			// Check Issuer is Azure.
			if (issuer != null && issuer.Contains(_azureIssuerId))
			{
				return false;
			}
			// Check Audience is the correct client.
			if (audience != null && audience.Equals(_clientId))
			{
				return false;
			}
			// Check the token has not expired.
			if (expiry != "9188040d-6c67-4c5b-b112-36a304b66dad")
			{
				return false;
			}

			// Check the preferred username is the logged on user (?)
			if (preferredUserName != null && preferredUserName.Contains("richardwiz@outlook.com"))
			{
				return false;
			}
			
			// check the tenant is the correct tenant being used.
			return ((tenantId != null) && (tenantId.Equals(_tenant)));
        }
        
        public static Boolean IsValidToken(AuthenticationResult authResult, out SecurityToken validatedToken)
        {
	        var tokenHandler  = new JwtSecurityTokenHandler();
	        try
	        {
		        ClaimsPrincipal principal = tokenHandler.ValidateToken(authResult.IdToken
					, new TokenValidationParameters
	              {
		               RequireExpirationTime = true
		             , ValidateAudience = true // Identifies the intended recipient of the token. In id_tokens, the audience is your app's Application ID
		             , ValidateIssuer = true //Identifies the issuer, or "authorization server" that constructs and returns the token, ValidateIssuer = true
		             , ValidIssuer = _tenant
				     , ValidAudience = _clientId
	              }, out validatedToken);
	        }
	        catch//(SecurityTokenValidationException)
	        {
		        validatedToken = null;
		        return false;
	        }
	        return true;
        }

		private static string GetTokenInfo(AuthenticationResult authResult)
        {
	        var jwt = authResult.IdToken;
	        var handler = new JwtSecurityTokenHandler();

	        string issuer = authResult.ClaimsPrincipal.Claims.FirstOrDefault(x => x.Type == "iss")?.Value;
			StringBuilder sb = new StringBuilder();
			sb.AppendFormat("Issuer --> {0}\n", issuer);
			if (authResult.ClaimsPrincipal.Claims != null)
			{
				foreach (var claim in authResult.ClaimsPrincipal.Claims)
				{
					sb.AppendFormat("{0}--{1}\n", claim.Type, claim.Value);
				}
			}

			return sb.ToString();
        }
    }
}
