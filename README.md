# Salesforce Java OAuth clients

Dependency-free Java 17 command-line apps that sign a user into Salesforce using the OAuth 2.0 Authorization Code flow, then verify access to the Salesforce REST API. `SalesforcePkceApp` uses PKCE; `SalesforceNoPkceApp` is a separate variant that omits PKCE.

**Security note:** The no-PKCE variant has less protection against authorization-code interception. Use the PKCE variant unless your Salesforce app configuration requires a flow without PKCE. The client secret remains optional in the no-PKCE variant, but Salesforce may require it depending on the app configuration.

## Salesforce org setup

1. In **Setup > App Manager**, create a **New Connected App**.
2. Enable **OAuth Settings** and set the callback URL to exactly:
   `https://localhost:3000/atlas/callback`
3. Add the **Manage user data via APIs (api)** OAuth scope. The app does not request a refresh token.
4. For `SalesforcePkceApp`, enable PKCE for the authorization-code flow if your Connected App setup exposes that policy; this app sends a PKCE verifier. `SalesforceNoPkceApp` does not send a verifier, so use it only when the org's app configuration permits authorization-code flow without PKCE. That configuration may require a client secret.
5. Save the Connected App and copy its **Consumer Key**. Allow time for Salesforce's Connected App changes to take effect.
6. Authorize the user who will sign in:
   - Set the Connected App's permitted users policy to **Admin approved users are pre-authorized**, then grant the app to that user's profile or a permission set; or
   - Use **All users may self-authorize** if that matches your org's access policy.
7. Ensure the user is active, has API access (and any required profile/permission-set access), and is allowed to use the Connected App. If the org requires My Domain or a specific login domain, use it for `--login-url`.

**Named Credentials are not needed for this Java app.** They are Salesforce-side configuration used by Salesforce features such as Apex callouts. For this external app, the value to provide is the Connected App **Consumer Key** (client ID) and the org's login URL.

Some Connected App policies require the Consumer Secret during the authorization-code exchange. This app can send it from the `SALESFORCE_CLIENT_SECRET` environment variable if needed; do not put the secret in source code or share it.

## Local HTTPS callback certificate

The callback uses HTTPS, so the Java listener needs a PKCS#12 keystore with a certificate for `localhost`, and the browser must trust that certificate. For local development, create a self-signed certificate with the JDK:

```powershell
keytool -genkeypair -alias salesforce-localhost -keyalg RSA -keysize 2048 -validity 365 -storetype PKCS12 -keystore salesforce-localhost.p12 -dname "CN=localhost" -ext "SAN=dns:localhost,ip:127.0.0.1"
keytool -exportcert -alias salesforce-localhost -keystore salesforce-localhost.p12 -rfc -file salesforce-localhost.cer
```

`keytool` prompts for a keystore password. Import `salesforce-localhost.cer` into the current Windows user's **Trusted Root Certification Authorities** certificate store (for example, open the `.cer` file, choose **Install Certificate**, select **Current User**, and choose **Trusted Root Certification Authorities**). Only trust certificates you created yourself; remove this development certificate from the trust store when it is no longer needed. Other browsers may use a separate certificate store.

In PowerShell, set the keystore location and the same password used during certificate creation:

```powershell
$env:SALESFORCE_KEYSTORE_PATH = (Resolve-Path .\salesforce-localhost.p12).Path
$env:SALESFORCE_KEYSTORE_PASSWORD = "YOUR_LOCAL_KEYSTORE_PASSWORD"
```

Keep the keystore and certificate private to your development machine; do not commit them.

If your Connected App requires a client secret for the web server flow, set it in the same terminal before launching the app:

```powershell
$secret = Read-Host "Connected App Consumer Secret" -AsSecureString
$env:SALESFORCE_CLIENT_SECRET = [System.Net.NetworkCredential]::new("", $secret).Password
```

Clear the variable when finished with `Remove-Item Env:\SALESFORCE_CLIENT_SECRET`.

## Compile and run

From this directory, using JDK 17, compile both classes:

```powershell
javac --add-modules jdk.httpserver SalesforcePkceApp.java SalesforceNoPkceApp.java
```

Run the PKCE variant:

```powershell
java --add-modules jdk.httpserver SalesforcePkceApp --client-id YOUR_CONSUMER_KEY
```

Run the no-PKCE variant:

```powershell
java --add-modules jdk.httpserver SalesforceNoPkceApp --client-id YOUR_CONSUMER_KEY
```

For a sandbox, specify its login host:

```powershell
java --add-modules jdk.httpserver SalesforcePkceApp --client-id YOUR_CONSUMER_KEY --login-url https://test.salesforce.com
```

For the no-PKCE variant, use the same options with `SalesforceNoPkceApp`. For My Domain, use its HTTPS origin, for example `https://your-domain.my.salesforce.com`. Each app opens the browser for Salesforce sign-in, handles the redirect on the local callback, exchanges the authorization code (with PKCE only in `SalesforcePkceApp`), and calls `/services/data/` with the access token. After that succeeds, it runs a SOQL query for up to five Account records using REST API version 66.0 to verify record-query access. On success, it prints the Salesforce instance URL. The temporary access token remains in memory and is not displayed or saved.

The callback listener uses local port `3000`; make sure it is available and that local security software permits loopback traffic. The callback URL in the Connected App must match exactly. The browser must trust the certificate or it will reject the HTTPS redirect.
