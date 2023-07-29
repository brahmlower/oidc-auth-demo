# Example OIDC Consumer

This is an example service that demonstrates using OIDC for authentication and getting profile details. It's only meant for local development, testing, and reference for future projects.

## Development

You'll need to configure an Google OIDC client application first.

Copy the example service config and update it with the details you've set for your OIDC application. Googles OIDC apps require that you set a domain to be redirected to, so you'll need to include that domain in your `/etc/hosts` file.

```
##
# Host Database
##

127.0.0.1   example.com
```

```shell
cp example.service.toml service.toml
```

Now run the application:

```shell
cargo run
```

Browse to `http://example.com:9090/`, and then you should be able to click "Login", be redirected to the google auth page to choose the account to use, and to allow the application. You'll then be redirected back to the exmaple site and should see your profile details.
