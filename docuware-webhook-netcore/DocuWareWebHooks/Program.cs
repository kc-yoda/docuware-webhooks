
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace DocuWareWebHooks
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.

            builder.Services.AddControllers();
            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();
            app.UseAuthorization();
            app.MapControllers();

            app.Use(async (context, next) =>
            {
                context.Request.EnableBuffering();
                using (var reader = new StreamReader(context.Request.Body, Encoding.UTF8, leaveOpen: false))
                {
                    string requestBody = await reader.ReadToEndAsync();
                    context.Request.Body.Position = 0; // Rewind the stream for subsequent reads

                    var signature = context.Request.Headers["x-docuware-signature"];

                    string secretKey = Environment.GetEnvironmentVariable("DW_PASSPHRASE") ?? "key-not-set";
                    byte[] keyBytes = Encoding.UTF8.GetBytes(secretKey);

                    //minify the request body to a JSON string
                    requestBody = JsonSerializer.Serialize(JsonSerializer.Deserialize<JsonDocument>(requestBody), new JsonSerializerOptions()
                    {
                        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping // This allows us to keep the JSON format without escaping characters
                    });

                    byte[] requestBodyBytes = Encoding.UTF8.GetBytes(requestBody);

                    using (var hmac = new HMACSHA512(keyBytes))
                    {
                        byte[] computedHash = hmac.ComputeHash(requestBodyBytes);
                        string expectedSignature = Convert.ToHexString(computedHash).ToLower(); // Or hex string, depending on client's format

                        bool validated = (signature == expectedSignature);
                        if (!validated)
                        {
                            // Log the payload or process it as needed
                            // For demonstration, we will just return a success response
                            context.Response.StatusCode = 403;
                            await context.Response.WriteAsJsonAsync(new { message = "MiddleWare - DocuWare webhook received successfully", expectedsignature = signature, actualsignature = expectedSignature, payload = requestBody, validationmessage = "The supplied signature is invalid for the payload received." });
                            return;
                        }
                        else
                        {
                            // Add the validated signature to the request headers
                            context.Request.Headers.TryAdd("x-signature-validation", expectedSignature);

                            await next(context);
                        }
                    }

                }
            });

            app.Run();
        }
    }
}
