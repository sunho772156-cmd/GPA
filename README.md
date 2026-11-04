# Secret Mode GPA Calculator

GPA entries are encrypted in the browser with Web Crypto before they are sent to the account API. Cloudflare D1 stores the username, a salted authentication verifier, and the AES-GCM ciphertext; it never receives the GPA values or the encryption key. The password is not sent to the API. A separate key derived from it is used for account authentication.

## Account behavior

- Users create an account with a site-specific username and password. No Google account or email address is used.
- The password is processed with PBKDF2-HMAC-SHA-256 (600,000 rounds), then HKDF derives separate authentication and AES-256-GCM encryption keys.
- A fresh random 96-bit nonce is generated for each AES-GCM save. The account name is authenticated as additional data.
- The app keeps derived keys in the current tab's `sessionStorage`; it does not store the plaintext grades there. Logging out clears that tab's session and grade inputs.
- The same username and password can decrypt the saved vault in another browser.
- There is no password reset or recovery key. If a user loses the password, their encrypted grades cannot be recovered.
- The API rate-limits repeated login attempts and uses revision checks to avoid silently overwriting changes made in another browser.

## Deploy the account API

The repository started as a static page. GitHub Pages does not run the `functions/` API handlers, so account creation and cross-browser sync require Cloudflare Pages Functions and a D1 database.

1. Create a Cloudflare Pages project connected to this GitHub repository and the `main` branch. Set the build command to empty and the build output directory to `.` (the repository root). Cloudflare Pages discovers the `functions/` routes from the repository.
2. Create a Cloudflare D1 database named `secret-mode-gpa`.
3. In the Pages project's **Settings → Functions → D1 database bindings**, bind that database to the variable `DB`.
4. Apply the schema from the repository root with Wrangler:

   ```powershell
   npx wrangler d1 execute secret-mode-gpa --remote --file=migrations/0001_user_vaults.sql
   ```

5. Deploy the Pages project over HTTPS. Once deployed, every push to `main` can publish the updated page and API together.

For local development, bind a local D1 database named `DB` when running `wrangler pages dev` and apply the same migration locally.

## Privacy boundary

The API validates authentication and stores/returns ciphertext; it has no decryption endpoint. The server operator can see usernames, IP addresses handled by Cloudflare, account activity, and ciphertext, and can delete or replace stored ciphertext. AES-GCM will reject modified ciphertext, but the operator can still deny service or replay an older valid ciphertext.

This protects data from someone who can inspect the database or API responses while the deployed client code remains trustworthy. Because a website operator controls the JavaScript sent to browsers, an operator who deliberately publishes modified client code could capture a password or unencrypted grades during entry. The app calls this out during signup; no browser-only website can promise protection from its own maliciously changed code or a compromised device.
