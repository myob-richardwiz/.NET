using System;
using System.Collections.Immutable;
using Microsoft.AspNetCore.Builder;

namespace Cerberus
{
    public static class ApplicationBuilderExtensions
	{
	    public static void UseAccessControl(this IApplicationBuilder builder, string clientId, string authorityHost, string redirectUri)
	    {
		    builder.UseIdentityServer(clientId, authorityHost, redirectUri);
	    }
	    public static void UseIdentityServer(this IApplicationBuilder builder, string clientId, string authorityHost, string redirectUri)
	    {
		    authorityHost = $"{authorityHost}/identity";

		    builder.UseIdentityServer(clientId, authorityHost, redirectUri);
	    }

    }
}