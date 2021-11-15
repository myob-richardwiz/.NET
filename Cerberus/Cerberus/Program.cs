using Microsoft.Identity.Client;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

namespace Cerberus
{
    class Program
    {
		// The Client ID is used by the application to uniquely identify itself to Azure AD.
		static string _clientId = System.Configuration.ConfigurationManager.AppSettings["ClientId"];

		// RedirectUri is the URL where the user will be redirected to after they sign in.
		static string _redirectUri = System.Configuration.ConfigurationManager.AppSettings["RedirectUri"];

	    // Tenant is the tenant ID (e.g. contoso.onmicrosoft.com, or 'common' for multi-tenant)
	    static string _tenant = System.Configuration.ConfigurationManager.AppSettings["Tenant"];
	    
	    // Scopes are the security settings that tell what your are allowed to do with the Application
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
			AuthenticationResult result = GetIdToken(myobApp).Result;
            
            if (result != null)
            {
	            SecurityToken validatedToken;
	            //ClaimsPrincipal principal = IsValidToken(result, out validatedToken); // Validate via open id connect
	            if (IsValidToken(result))
	            {
		            Console.WriteLine(GetTokenInfo(result));
	            }
	            else
	            {
		            Console.WriteLine( "Token Invalid");
	            }
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
		        Console.WriteLine(res);
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
	        
			// Check Audience is the correct client.
			if (audience != null && !audience.Equals(_clientId))
			{
				return false;
			}
			// Check the token has not expired.
			long unixSeconds = Convert.ToInt32(expiry);
			DateTimeOffset expiryTimeOffset = DateTimeOffset.FromUnixTimeSeconds( unixSeconds);
			if (DateTime.Compare(expiryTimeOffset.LocalDateTime, DateTime.Now) < 0 ) // expiry is earlier than now. ie.has expired.
			{
				return false;
			}

			// Check the preferred username is the logged on user.
			var winId = System.Security.Principal.WindowsIdentity.GetCurrent();
			if (preferredUserName != null && preferredUserName.IndexOf(winId.Name, StringComparison.OrdinalIgnoreCase) < 0)
			{
				return false;
			}
			
			// check the tenant is the correct tenant being used.
			return ((tenantId != null) && (tenantId.Equals(_tenant)));
        }
        
        public static ClaimsPrincipal IsValidToken(AuthenticationResult authResult, out SecurityToken validatedToken)
        {
	        var tokenHandler  = new JwtSecurityTokenHandler();
	        ClaimsPrincipal principal = new ClaimsPrincipal();
	        
	        var authorityEndpoint = "https://login.microsoftonline.com";
	        var openIdConfigurationEndpoint = $"{authorityEndpoint}.well-known/openid-configuration";
	        //IConfigurationManager<OpenIdConnectConfiguration> configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(openIdConfigurationEndpoint, new OpenIdConnectConfigurationRetriever());
	        //OpenIdConnectConfiguration openIdConfig = await configurationManager.GetConfigurationAsync(CancellationToken.None);
	    
			        
	        try
	        {
		        principal = tokenHandler.ValidateToken(authResult.IdToken
					, new TokenValidationParameters
	              {
						  ValidateIssuer = true
						, ValidIssuer = "https://login.microsoftonline.com"//Identifies the issuer, or "authorization server" that constructs and returns the token
						, ValidateAudience = true
						, ValidAudience = _clientId // Identifies the intended recipient of the token. In id_tokens, the audience is your app's Application ID
						, ValidateIssuerSigningKey = true
						//, IssuerSigningKeys = openidconfig.SigningKeys
						, RequireExpirationTime = true
						, ValidateLifetime = true
						, RequireSignedTokens = true
	              }, out validatedToken);
	        }
	        catch//(SecurityTokenValidationException)
	        {
		        validatedToken = null;
		        return null;
	        }
	        return principal;
        }

		private static string GetTokenInfo(AuthenticationResult authResult)
        {
	        var jwt = authResult.IdToken;
	        var handler = new JwtSecurityTokenHandler();

	        string issuer = authResult.ClaimsPrincipal.Claims.FirstOrDefault(x => x.Type == "iss")?.Value;
	        string expiry = authResult.ClaimsPrincipal.Claims.FirstOrDefault(x => x.Type == "exp")?.Value;
	        long unixSeconds = Convert.ToInt32(expiry);
	        DateTimeOffset expiryTimeOffset = DateTimeOffset.FromUnixTimeSeconds( unixSeconds).LocalDateTime;
			StringBuilder sb = new StringBuilder();
			sb.AppendFormat("Issuer --> {0}\n", issuer);
			sb.AppendFormat("Token will Expire at {0}. \nTime is {1} now.\n",DateTimeOffset.FromUnixTimeSeconds( unixSeconds).LocalDateTime, DateTime.Now);
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
