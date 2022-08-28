using Microsoft.AspNetCore.Mvc;

namespace API.Controllers
{
    [ApiController]
    [Route(template: "api/[controller]")]
    public class BaseAPIController : ControllerBase { }
}
