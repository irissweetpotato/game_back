# Multi-domain / multi-API-key configuration

The server still supports the old single-project variables:

```env
API_KEY=one_api_key
KEITARO_TRACKER=https://keitaro-domain.example
KEITARO_TOKEN=one_keitaro_token
```

For multiple applications/domains on one VDS, use one of these formats.

## Recommended: indexed variables

```env
API_KEY_1=api_key_for_first_app
KEITARO_TRACKER_1=https://first-keitaro.example
KEITARO_TOKEN_1=first_keitaro_token
DOMAINS_1=domain-one.example,www.domain-one.example

API_KEY_2=api_key_for_second_app
KEITARO_TRACKER_2=https://second-keitaro.example
KEITARO_TOKEN_2=second_keitaro_token
DOMAINS_2=domain-two.example,www.domain-two.example
```

Indexes may be any amount: `_1`, `_2`, `_3`, etc. The request is matched by `x-api-key`; the matching set supplies the Keitaro URL and token.

`DOMAINS_N` is optional. The backend does not require a fixed number of domains. Nginx can route multiple domains to the same Node.js process.

## JSON option

```env
API_CONFIGS=[{"api_key":"api_key_1","keitaro_url":"https://keitaro-1.example","keitaro_token":"token_1","domains":["domain-one.example"]},{"api_key":"api_key_2","keitaro_url":"https://keitaro-2.example","keitaro_token":"token_2"}]
```

## Comma-separated option

```env
API_KEYS=api_key_1,api_key_2
KEITARO_TRACKERS=https://keitaro-1.example,https://keitaro-2.example
KEITARO_TOKENS=token_1,token_2
```

The counts must match.

## ip-api filtering

The backend now requests these fields from ip-api:

```txt
proxy, hosting, isp, org, as
```

The existing proxy logic is preserved. Additionally, the request becomes a non-pass if:

```txt
hosting === true
```

or if any of these strings is present in `isp`, `org`, or `as`:

```txt
TEST
TEST2
TEST3
```

The check is case-insensitive.
