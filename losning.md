# Övning 3.3: Dekryptera det hemliga meddelandet

Daniel Aldemir  
.NET-utbildningen TUC, vecka 2



## 1. Krypteringsmetod

Programmet använder symmetrisk kryptering med AES-256-GCM.

Jag såg i Program.cs att AesGcm används både när programmet krypterar och dekrypterar. Nyckeln skapas från ett lösenord med PBKDF2 och blir 32 bytes, alltså 256 bitar.

Det är symmetrisk kryptering eftersom samma nyckel används för att kryptera och dekryptera informationen.



## 2. Arbetsgång

Jag började med att klona repot och starta programmet.
När programmet startade såg jag texten "Select option (1) or enter secret phrase". Då förstod jag att det fanns en dold funktion om man skrev in rätt fras.
Jag testade först att kryptera ett eget meddelande för att förstå hur programmet fungerade. Då skapades bland annat filerna secret.bin och password.b64.

Jag såg att lösenordet sparades i Base64. Base64 är inte kryptering utan bara ett annat sätt att skriva information. När jag avkodade password.b64 fick jag därför tillbaka lösenordet i klartext.

Sedan tittade jag i appsettings.json och hittade "SecretPhraseB64: a3VyZGlza2Fyw6R2ZW4="
Jag avkodade den från Base64 och fick kurdiskaräven.

När jag skrev in kurdiskaräven i programmet kom jag in i den dolda menyn.

Jag såg också att den hemliga frasen och lösenordet till krypteringen är två olika saker. Den hemliga frasen används för att komma in i den dolda menyn. Lösenordet i password.b64 används för att skapa nyckeln som behövs för att dekryptera filen.

Jag lade sedan mappen från zip-filen i programmets datamapp, startade programmet igen och skrev in den hemliga frasen. Sedan valde jag rätt mapp och programmet dekrypterade meddelandet.


## 3. Meddelandet

Grattis, ni har lyckats dekryptera meddelandet! 🎉 Det här visar att ni kan analysera kod, hitta dolda funktioner och förstå hur kryptering fungerar i praktiken. 💻🔐 Kom ihåg: Riktig säkerhet bygger aldrig på att gömma koden – utan på stark kryptering, korrekt nyckelhantering och god design.


## 4. Motivering

Problemet är inte själva AES-GCM krypteringen utan hur lösenordet hanteras. Lösenordet ligger Base64-kodat i password.b64 bredvid den krypterade filen, så om någon får tag på båda filerna är det ganska enkelt att få fram lösenordet och dekryptera meddelandet. Felet hör hemma i A04 Cryptographic Failures i OWASP Top 10:2025 eftersom algoritmen i sig är stark, men symmetrisk kryptering är bara så stark som nyckeln är hemlig, och här ligger nyckeln bredvid filen den ska skydda.

Jag skulle därför inte spara lösenordet tillsammans med den krypterade filen. Det som hade stoppat mig är att ta bort rad 99 i Program.cs, alltså `File.WriteAllText(pwdPath, Convert.ToBase64String(...))`, och i stället låta DecryptFlow fråga efter lösenordet med samma ReadPassword som EncryptFlow redan använder på rad 64. Då finns lösenordet bara i minnet och sparas aldrig på disk.

Den hemliga frasen bör inte heller ligga i appsettings.json om filen finns i Git. Hemligheter och nycklar bör sparas på ett säkrare ställe och inte direkt i projektets kod eller konfigurationsfiler.