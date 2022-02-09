# akamai-proxy Cloudflare Worker

This code implements a [Cloudflare worker](https://developers.cloudflare.com/workers/) utilizing Cloudflare's [Wrangler CLI](https://developers.cloudflare.com/workers/cli-wrangler/install-update) that caches an Akamai header using an edge instance of Redis ([Upstash](https://www.upstash.com)). 

### 1. Install Wrangler CLI
See [Cloudflare's instructions](https://developers.cloudflare.com/workers/cli-wrangler/install-update) for further details but run the following command to get started:

`npm i @cloudflare/wrangler -g`

### 2. Authenticate Wrangler CLI
[Authenticate](https://developers.cloudflare.com/workers/cli-wrangler/authentication) to your own instance of Cloudflare with the following command:

`wrangler login`

### 3. Generate New Worker
[Generate a new project](https://developers.cloudflare.com/workers/cli-wrangler/commands#generate) by directly cloning this repo.

`wrangler generate akamai-proxy https://github.com/okta-dfuhrimanak/akamai-proxy`

### 4. Setup an Upstash account
[Setup](https://docs.upstash.com/redis#create-account) a free account with Upstash.

### 5. Create a database
1. [Create a new database](https://docs.upstash.com/redis#create-a-database)
1.  Copy the `endpoint`
1.  Scroll down to the `REST API` section, click on `Javascript (Fetch)`, and copy the `Bearer` token.

### 6. Update Cloudflare Config
1. Using the Wrangler CLI, set the bearer token `wrangler secret put UPSTASH_TOKEN`. You will then be prompted to enter the token.
1. In the `wrangler.toml` file, add the following and set the values appropriately:
```toml
[vars]
# This is your custom domain configured in Okta.
ORIGIN = "https://subway.atko.rocks"
# Get this value from your Upstash account.
UPSTASH_ENDPOINT = "https://eu1-artistic-bass-33019.upstash.io"
# Change this if you want to modify the TTL for stashed data.
UPSTASH_EXPIRE = 300
# Makes testing easier since the header is 'hardcoded'.
SCORE = 50
```
Your `account_id` should have been set in the config during the project creation but, if not, double check it and set it. 

### 7. Publish the Worker
Run the following to [push the worker to your Cloudflare account](https://developers.cloudflare.com/workers/cli-wrangler/commands#publishing-to-workersdev).

`wrangler publish`

