using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;

public static class VaultApp
{
	private static string SecretPhrase = string.Empty;

	public static void Main()
	{
		var config = new ConfigurationBuilder()
			.SetBasePath(AppContext.BaseDirectory)
			.AddJsonFile("appsettings.json", optional: false)
			.Build();

		var enc = config.GetSection("Encryption");
		int iterations = enc.GetValue<int>("Iterations");
		int saltSize = enc.GetValue<int>("SaltSizeBytes");
		int nonceSize = enc.GetValue<int>("NonceSizeBytes");
		string passwordFile = enc.GetValue<string>("PasswordFile") ?? "password.b64";
		string cipherFile = enc.GetValue<string>("CipherTextFile") ?? "secret.bin";
		string dataRoot = enc.GetValue<string>("DataRoot") ?? "data";
		string secretPhraseB64 = enc.GetValue<string>("SecretPhraseB64") ?? string.Empty;

		// BRIST:
		// Den hemliga frasen ligger i appsettings.json som Base64.
		// Base64 ser oläsligt ut, men det är inte kryptering.
		// Det går enkelt att göra om Base64 tillbaka till vanlig text.
		//
		// BÄTTRE:
		// Hemliga uppgifter bör inte ligga direkt i konfigurationsfilen.
		// De kan istället lagras på ett säkrare ställe, till exempel
		// i environment variables eller en tjänst för hemligheter.

		if (!string.IsNullOrEmpty(secretPhraseB64))
		{
			try { SecretPhrase = Encoding.UTF8.GetString(Convert.FromBase64String(secretPhraseB64)); }
			catch { SecretPhrase = string.Empty; }
		}

		string projectRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", ".."));
		string dataRootPath = Path.Combine(projectRoot, dataRoot);
		Directory.CreateDirectory(dataRootPath);

		Console.WriteLine("=== Strawberry Secret Vault ===");
		Console.WriteLine("1) Encrypt new message");
		Console.Write("Select option (1) or enter secret phrase: ");
		var choice = Console.ReadLine();

		// BRIST:
		// Här räcker det att känna till en enda hemlig fras
		// för att få tillgång till dekrypteringsdelen.
		//
		// Om någon lyckas få tag på frasen kan personen alltså
		// komma vidare till de sparade meddelandena.
		//
		// BÄTTRE:
		// Man skulle kunna ha en säkrare inloggning eller annan
		// kontroll av vem som faktiskt får dekryptera meddelanden.

		if (string.Equals(choice, SecretPhrase, StringComparison.Ordinal))
		{
			DecryptFlow(dataRootPath, cipherFile, passwordFile);
			return;
		}

		if (choice == "1")
		{
			EncryptFlow(dataRootPath, cipherFile, passwordFile, iterations, saltSize, nonceSize);
		}
		else
		{
			Console.WriteLine("Unknown option.");
		}
	}

	private static void EncryptFlow(string dataRootPath, string cipherFile, string passwordFile, int iterations, int saltSize, int nonceSize)
	{
		var folder = DateTime.UtcNow.ToString("yyyyMMdd_HHmmssfff");
		var outDir = Path.Combine(dataRootPath, folder);
		Directory.CreateDirectory(outDir);

		Console.Write("Enter message to encrypt: ");
		var message = Console.ReadLine() ?? string.Empty;
		var password = ReadPassword("Enter password (will be stored encoded): ");
		if (string.IsNullOrWhiteSpace(password)) { Console.WriteLine("Password empty."); return; }

		// BRIST:
		// Flera säkerhetsinställningar hämtas från appsettings.json.
		// Programmet kontrollerar inte tydligt här om värdena är rimliga.
		//
		// Om någon råkar skriva fel värde i konfigurationen
		// kan krypteringen fungera dåligt eller sluta fungera.
		//
		// BÄTTRE:
		// Programmet bör kontrollera värdena innan de används.

		byte[] salt = RandomNumberGenerator.GetBytes(saltSize);

		// BRA:
		// Här används ett slumpmässigt salt tillsammans med lösenordet.
		// Saltet gör det svårare för en angripare att gissa lösenord
		// genom färdiga listor med redan uträknade värden.

		byte[] key = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA512, 32);

		byte[] nonce = RandomNumberGenerator.GetBytes(nonceSize);
		int tagSize = 16;

		// BRA:
		// AES-GCM är en modern metod för kryptering.
		// Den gör både innehållet oläsligt och hjälper till att upptäcka
		// om någon har ändrat den krypterade informationen.
		//
		// BÄTTRE:
		// Storleken på nonce bör kontrolleras så att programmet
		// alltid använder ett värde som passar AES-GCM.

		using var aes = new AesGcm(key, tagSize);
		byte[] plaintext = Encoding.UTF8.GetBytes(message);
		byte[] ciphertext = new byte[plaintext.Length];
		byte[] tag = new byte[tagSize];
		aes.Encrypt(nonce, plaintext, ciphertext, tag);

		const uint magic = 0x53455243; // SERC
		byte version = 1;
		if (salt.Length > 255 || nonce.Length > 255 || tag.Length > 255) { Console.WriteLine("Component too large."); return; }
		var cipherPath = Path.Combine(outDir, cipherFile);
		using (var fs = File.Create(cipherPath))
		{
			Span<byte> header = stackalloc byte[4 + 1 + 3 + 4];
			BinaryPrimitives.WriteUInt32BigEndian(header[..4], magic);
			header[4] = version;
			header[5] = (byte)salt.Length;
			header[6] = (byte)nonce.Length;
			header[7] = (byte)tag.Length;
			BinaryPrimitives.WriteInt32BigEndian(header.Slice(8,4), iterations);

			// BRIST:
			// Filen innehåller extra information om hur den ska läsas,
			// till exempel storlekar och antal iterationer.
			//
			// Den informationen har inte samma skydd som själva meddelandet.
			//
			// BÄTTRE:
			// Även denna information kan skyddas så att programmet märker
			// om någon försöker ändra den.

			fs.Write(header);
			fs.Write(salt);
			fs.Write(nonce);
			fs.Write(tag);
			fs.Write(ciphertext);
		}

		var pwdPath = Path.Combine(outDir, passwordFile);

		// STOR BRIST:
		// Lösenordet sparas i en fil på datorn.
		//
		// Det sparas som Base64, men Base64 är inte kryptering.
		// Vem som helst som kommer åt filen kan enkelt läsa lösenordet.
		//
		// Det blir ungefär som att låsa ett kassaskåp
		// och sedan lägga nyckeln bredvid kassaskåpet.
		//
		// BÄTTRE:
		// Lösenordet ska inte sparas tillsammans med den krypterade filen.
		// Användaren bör istället skriva in lösenordet igen när
		// meddelandet ska dekrypteras.

		File.WriteAllText(pwdPath, Convert.ToBase64String(Encoding.UTF8.GetBytes(password)) + Environment.NewLine);

		Console.WriteLine($"Encrypted and saved to '{cipherPath}'.");
		Console.WriteLine("NOTE: Storing password is insecure (demo only).");
	}

	private static void DecryptFlow(string dataRootPath, string cipherFile, string passwordFile)
	{
		if (!Directory.Exists(dataRootPath)) { Console.WriteLine("No data directory."); return; }
		var folders = Directory.GetDirectories(dataRootPath)
			.OrderBy(d => d)
			.Where(d => File.Exists(Path.Combine(d, cipherFile)) && File.Exists(Path.Combine(d, passwordFile)))
			.ToList();

		if (folders.Count == 0) { Console.WriteLine("No encrypted messages."); return; }

		Console.WriteLine("Encrypted message folders:");
		for (int i = 0; i < folders.Count; i++)
			Console.WriteLine($"[{i+1}] {Path.GetFileName(folders[i])}");

		Console.Write("Select number to decrypt: ");
		if (!int.TryParse(Console.ReadLine(), out int sel) || sel < 1 || sel > folders.Count)
		{
			Console.WriteLine("Invalid.");
			return;
		}

		var chosen = folders[sel - 1];
		var cipherPath = Path.Combine(chosen, cipherFile);
		var pwdPath = Path.Combine(chosen, passwordFile);

		// BRIST:
		// Programmet hämtar själv lösenordet från filen.
		//
		// Det betyder att användaren inte behöver känna till
		// lösenordet som användes när meddelandet krypterades.
		//
		// Om någon kommer in i denna del av programmet finns lösenordet
		// redan sparat åt personen.
		//
		// BÄTTRE:
		// Be användaren skriva in lösenordet vid dekryptering
		// istället för att läsa det från en fil.

		var b64 = File.ReadAllText(pwdPath).Trim();
		string password;

		try
		{
			password = Encoding.UTF8.GetString(Convert.FromBase64String(b64));
		}

		// BRIST:
		// Om Base64 inte fungerar använder programmet ändå innehållet
		// från filen som lösenord.
		//
		// Det gör att programmet accepterar en felaktig fil
		// istället för att säga att något är fel.
		//
		// BÄTTRE:
		// Om filen har fel format bör programmet stoppa
		// och visa ett tydligt felmeddelande.

		catch
		{
			password = b64;
		}

		try
		{
			string plaintext = Decrypt(cipherPath, password);
			Console.WriteLine("Decrypted message:\n" + plaintext);
		}
		catch (Exception ex)
		{
			// MÖJLIG BRIST:
			// Programmet visar det riktiga tekniska felmeddelandet direkt.
			//
			// I ett större system kan sådana fel ibland avslöja
			// information om hur programmet fungerar.
			//
			// BÄTTRE:
			// Användaren kan få ett enklare felmeddelande,
			// medan det riktiga felet sparas i en logg för utvecklaren.

			Console.WriteLine("Decryption failed: " + ex.Message);
		}
	}

	private static string Decrypt(string filePath, string password)
	{
		using var fs = File.OpenRead(filePath);

		Span<byte> header = stackalloc byte[4 + 1 + 3 + 4];

		if (fs.Read(header) != header.Length)
			throw new InvalidDataException("Header too short");

		if (BinaryPrimitives.ReadUInt32BigEndian(header[..4]) != 0x53455243)
			throw new InvalidDataException("Bad magic");

		byte version = header[4];

		if (version != 1)
			throw new InvalidDataException("Unsupported version");

		int saltLen = header[5];
		int nonceLen = header[6];
		int tagLen = header[7];
		int iterations = BinaryPrimitives.ReadInt32BigEndian(header.Slice(8,4));

		// BRIST:
		// Programmet läser flera värden direkt från filen
		// och använder dem utan att först kontrollera om de är rimliga.
		//
		// Om filen har blivit ändrad eller är trasig kan den innehålla
		// konstiga värden.
		//
		// BÄTTRE:
		// Kontrollera värdena innan programmet använder dem.

		byte[] salt = new byte[saltLen];
		fs.ReadExactly(salt);

		byte[] nonce = new byte[nonceLen];
		fs.ReadExactly(nonce);

		byte[] tag = new byte[tagLen];
		fs.ReadExactly(tag);

		byte[] ciphertext = new byte[fs.Length - fs.Position];
		fs.ReadExactly(ciphertext);

		byte[] key = Rfc2898DeriveBytes.Pbkdf2(
			password,
			salt,
			iterations,
			HashAlgorithmName.SHA512,
			32);

		using var aes = new AesGcm(key, tagLen);

		byte[] plaintext = new byte[ciphertext.Length];

		aes.Decrypt(nonce, ciphertext, tag, plaintext);

		// MÖJLIG FÖRBÄTTRING:
		// Krypteringsnyckeln och den dekrypterade texten ligger kvar
		// i datorns minne en stund efter att de har använts.
		//
		// I system med väldigt höga säkerhetskrav kan man
		// försöka rensa sådan känslig information från minnet
		// så snart den inte längre behövs.

		return Encoding.UTF8.GetString(plaintext);
	}

	private static string ReadPassword(string prompt)
	{
		Console.Write(prompt);

		var sb = new StringBuilder();

		while (true)
		{
			var key = Console.ReadKey(true);

			if (key.Key == ConsoleKey.Enter)
			{
				Console.WriteLine();
				break;
			}

			if (key.Key == ConsoleKey.Backspace)
			{
				if (sb.Length > 0)
				{
					sb.Length--;
					Console.Write("\b \b");
				}

				continue;
			}

			if (!char.IsControl(key.KeyChar))
			{
				sb.Append(key.KeyChar);
				Console.Write('*');
			}
		}

		// BRA:
		// När användaren skriver lösenordet visas bara stjärnor.
		// Det gör att någon som tittar på skärmen inte ser lösenordet.
		//
		// Detta skyddar däremot inte lösenordet efteråt,
		// eftersom lösenordet senare sparas i en fil som Base64.

		return sb.ToString();
	}
}
