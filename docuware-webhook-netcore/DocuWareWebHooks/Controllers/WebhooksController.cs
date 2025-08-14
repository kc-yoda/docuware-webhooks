using System.Reflection.PortableExecutable;
using System.Text;
using Microsoft.AspNetCore.Mvc;

namespace DocuWareWebHooks.Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class WebhooksController : ControllerBase
    {

        // /webhooks/docuware
        [Route("docuware")]
        [HttpPost]
        public async Task<IActionResult> DocuWare([FromBody] object payload)
        {
            Request.Body.Position = 0; // Rewind the stream for reading
            string rawBody = string.Empty;

            using (var reader = new StreamReader(Request.Body, Encoding.UTF8, leaveOpen: false))
            {
                rawBody = await reader.ReadToEndAsync();
            }

            var signature = Request.Headers["x-docuware-signature"];
            var validatedsignature = Request.Headers["x-signature-validation"]; //middleware should have injected header here
            return Ok(new { message = $"Validation processed results at {DateTime.Now} with the validation result: {(signature == validatedsignature)}", raw = rawBody, paylod = payload, expectedsignature = signature, actualsignature = validatedsignature, valid = (signature == validatedsignature) });
        }
    }
}
