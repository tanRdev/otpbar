# Treat native OAuth as a public-client flow

OTPBar authorizes Gmail with Authorization Code plus PKCE and high-entropy state, using an ephemeral loopback callback bound to an IP literal before opening the browser. A distributed client secret is never treated as confidential or required for security. This follows the native-app threat model and removes reliance on a secret every installed copy necessarily exposes.
