# Strawberry Secret Vault

- Encrypts a user-provided message.
- Stores each encrypted message.


## Project Structure
```
appsettings.json         # Global encryption + app config
Program.cs               # Main application logic
jordgubben.csproj
/ data/                  # (git-ignored) timestamped encrypted message folders
```

Each run (encryption) creates: `data/<UTC_yyyyMMdd_HHmmssfff>/secret.bin` and `password.b64`.

---
## Build & Run
Requires .NET 10 SDK.
```powershell
# Build
dotnet build

# Run (interactive)
dotnet run 
```

Main menu shows only:
```
=== Strawberry Secret Vault ===
1) Encrypt new message
Select option (1) or enter secret phrase:
```

## File Format: `secret.bin`
Layout (all big endian for integers):
```
[4]  Magic bytes      = 'SERC' (0x53 0x45 0x52 0x43)
[1]  Version          = 0x01
[1]  Salt length (S)
[1]  Nonce length (N)
[1]  Tag length (T)
[4]  Iteration count (I)
[S]  Salt
[N]  Nonce
[T]  Tag (GCM authentication tag)
[..] Ciphertext (len = remaining bytes)
```
Key derivation: `key = PBKDF2(password, salt, I, SHA512, 32 bytes)`.
Encryption: `AES-256-GCM(nonce, plaintext) -> (ciphertext, tag)`.


---
## Quick Decrypt Without App (Pseudocode)
```
Read header -> get S,N,T,I
Read salt, nonce, tag, ciphertext
key = PBKDF2(password, salt, I, SHA512, 32)
AES-GCM Decrypt(nonce, ciphertext, tag) -> plaintext