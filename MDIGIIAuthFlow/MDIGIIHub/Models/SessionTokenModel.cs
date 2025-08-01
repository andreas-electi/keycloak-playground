namespace MDIGIIHub.Models;

public class SessionTokenModel
{
	public string Sub { get; set; } = string.Empty; // User ID
	public string ServiceId { get; set; } = string.Empty;
	public long Iat { get; set; } // Issued at timestamp
	public long Exp { get; set; } // Expiration timestamp
	public List<string>? Roles { get; set; }
}