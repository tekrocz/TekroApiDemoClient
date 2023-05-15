using System.Net.Mime;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace TekroApiDemoClient;

/// <summary>
/// This is a demo client implementation that demonstrates how to authorize requests to TekroAPI.
/// There are two examples implemented: one for GET request (request without body), and one for POST request (request with json body).
/// The POST request example can be used for other requests with body, e.g. PUT, ...
///
/// Before using this demo client you need to fill your ApiToken and ApiSecretKey, as well as specify GET and/or POST request URLs that this demo client will use to perform requests.
/// All the values should be available for you from TekroAPI provider (contact support if you don't have one of those).
///
/// For a sake of simplicity, this demo client is implemented as console application with all required code in single class, showing example code for all the necessary steps to perform authorized requests.
///
/// For any questions or request, please contact support.
/// </summary>
internal class Program
{
    private const string ApiUrl = "https://api.tekro.cz"; // api base url
    private const string GetRequestUrl = $"{ApiUrl}/..."; // put the GET url here
    private const string PostRequestUrl = $"{ApiUrl}/..."; // put the POST url here

    private const string ApiToken = ""; // put your ApiToken here
    private const string ApiSecretKey = ""; // put your ApiSecretKey here

    static void Main(string[] args)
    {
        PerformGetRequestAsync().Wait(); // comment out if you do not want to perform GET request
        PerformPostRequestAsync().Wait(); // comment out if you do not want to perform POST request

        Console.WriteLine("Press any key to exit...");
        Console.ReadKey(); // wait for key press
    }

    /// <summary>
    /// Performs GET request asynchronously.
    /// </summary>
    private static async Task PerformGetRequestAsync()
    {
        Console.WriteLine($"Performing GET request to: {GetRequestUrl}");

        var httpRequestMessage = new HttpRequestMessage
        {
            Method = HttpMethod.Get,
            RequestUri = new Uri(GetRequestUrl)
        };

        // prepare auth headers and add them to the request message
        // timestamp and API token
        var unixTimeStamp = DateTimeOffset.Now.ToUnixTimeSeconds(); // cannot not be in future, cannot be more than 60 seconds in past.
        httpRequestMessage.Headers.Add("Api-Token", new[] { ApiToken });
        httpRequestMessage.Headers.Add("Authorization-Timestamp", new[] { $"{unixTimeStamp}" });

        // nonce and HMAC signature
        var nonce = GenerateNonceString();
        var hmac = CalculateHmacToken("", unixTimeStamp, nonce, ApiSecretKey); // for requests without body we do not calculate HMAC content hash (so we just pass empty string).
        httpRequestMessage.Headers.Add("Authorization", new[] { $"HMAC-SHA256 nonce=\"{nonce}\" signature=\"{hmac}\"" });

        using var httpClient = GetHttpClient();
        var getRequestResult = await httpClient.SendAsync(httpRequestMessage, CancellationToken.None);
        var getRequestResultContent = await getRequestResult.Content.ReadAsStringAsync();
        Console.WriteLine($"GET request result: {(int)getRequestResult.StatusCode}/{getRequestResult.ReasonPhrase}{Environment.NewLine}{getRequestResultContent}");
        Console.WriteLine();
    }

    /// <summary>
    /// Performs POST request asynchronously.
    /// </summary>
    private static async Task PerformPostRequestAsync()
    {
        Console.WriteLine($"Performing POST request to: {PostRequestUrl}");

        // send demo data along with request
        var requestBodyData = new
        {
            Message = "Hello from client!"
        };
        var requestBodyJson = JsonSerializer.Serialize(requestBodyData);
            
        var httpRequestMessage = new HttpRequestMessage
        {
            Method = HttpMethod.Post,
            RequestUri = new Uri(PostRequestUrl),
            Content = new StringContent(requestBodyJson, Encoding.UTF8, MediaTypeNames.Application.Json),
        };

        // prepare auth headers and add them to the request message
        // timestamp and API token
        var unixTimeStamp = DateTimeOffset.Now.ToUnixTimeSeconds(); // cannot not be in future, cannot be more than 60 seconds in past.
        httpRequestMessage.Headers.Add("Authorization-Timestamp", new[] { $"{unixTimeStamp}" });
        httpRequestMessage.Headers.Add("Api-Token", new[] { ApiToken });

        // calculate SHA256 hash for the request body content
        var requestBodyHash = CalculateSha256ContentAuthorizationHash(requestBodyJson);
        httpRequestMessage.Headers.Add("Authorization-Content-SHA256", new[] { requestBodyHash });

        // nonce and HMAC signature
        var nonce = GenerateNonceString();
        var hmac = CalculateHmacToken(requestBodyHash, unixTimeStamp, nonce, ApiSecretKey);
        httpRequestMessage.Headers.Add("Authorization", new[] { $"HMAC-SHA256 nonce=\"{nonce}\" signature=\"{hmac}\"" });

        using var httpClient = GetHttpClient();
        var postRequestResult = await httpClient.SendAsync(httpRequestMessage, CancellationToken.None);
        var postRequestResultContent = await postRequestResult.Content.ReadAsStringAsync();
        Console.WriteLine($"POST request result: {(int)postRequestResult.StatusCode}/{postRequestResult.ReasonPhrase}{Environment.NewLine}{postRequestResultContent}");
        Console.WriteLine();
    }

    /// <summary>
    /// Gets the <see cref="HttpClient"/> instance.
    /// </summary>
    private static HttpClient GetHttpClient()
    {
        return new HttpClient(); // just for simplicity, better to use IHttpClientFactory
    }

    /// <summary>
    /// Generates the unique nonce string. The nonce must be valid GUID (UUID v4).
    /// </summary>
    private static string GenerateNonceString()
    {
        var result = Guid.NewGuid().ToString("N");
        return result;
    }

    /// <summary>
    /// Calculates the HMAC (HMAC-SHA-256) hash from specified input values.
    /// </summary>
    /// <param name="contentAuthorizationHash">The content authorization SHA256 hash.</param>
    /// <param name="authorizationTimeStamp">The authorization timestamp.</param>
    /// <param name="nonce">The nonce string.</param>
    /// <param name="secretKey">The API secret key.</param>
    private static string CalculateHmacToken(string contentAuthorizationHash, long authorizationTimeStamp, string nonce, string secretKey)
    {
        // token for request with body: "Authorization-Content-SHA256;Authorization-Timestamp;nonce"
        // token for request without body: ";Authorization-Timestamp;nonce"

        if (contentAuthorizationHash == null) throw new ArgumentNullException(nameof(contentAuthorizationHash));
        if (string.IsNullOrEmpty(nonce)) throw new ArgumentNullException(nameof(nonce));
        if (string.IsNullOrEmpty(secretKey)) throw new ArgumentNullException(nameof(secretKey));

        var tokenMessage = $"{contentAuthorizationHash};{authorizationTimeStamp};{nonce}";
        var tokenMessageBytes = Encoding.UTF8.GetBytes(tokenMessage);
        var secretBytes = Encoding.UTF8.GetBytes(secretKey);

        using var hmac = new HMACSHA256(secretBytes);
        var hash = hmac.ComputeHash(tokenMessageBytes);
        var digest = Convert.ToBase64String(hash);
        return digest;
    }

    /// <summary>
    /// Calculates SHA256 hash from specified string.
    /// </summary>
    /// <param name="data">The data to calculate hash from.</param>
    private static string CalculateSha256ContentAuthorizationHash(string data)
    {
        using var sha256Hash = SHA256.Create();
        var bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(data));
        var builder = new StringBuilder();
        foreach (var t in bytes)
        {
            builder.Append(t.ToString("x2"));
        }

        return builder.ToString();
    }
}