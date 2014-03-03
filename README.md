# hubot-dnsmadeeasy
A hubot script for interacting with the DNS Made Easy v2 api

# Usage

## Environment variables
- `HUBOT_DME2_API_KEY`
- `HUBOT_DME2_API_SECRET`

## Help (`hubot help dns me`)
```
dns me create <hostname> <domain name> <address> <type> - creates a record in <domain name>
dns me delete <domain name> <record id> - deletes the record with id <record id> from <domain name>
dns me domains - returns a list of domains in DME account
dns me last <n> <action> - returns the last N results for <action> operations from the audit log
dns me log (max|count) - returns (max|count) entries from the audit log
dns me lookup <record> <domain name> - returns and results for <record> in <domain name>
dns me max results <n> - sets the allowed max results returned from audit log queries
dns me stats - returns a sparkline of query counts from DME
```

# Features
- Caching of data in hubot's brain
- role-based access control
- audit logging
- SPARKLINES!!!1111!!!!

## Caching
Hubot stores its cache in its brain under the key `dnsme_cche`

Hubot will cache ids for each domain registered with your DME account. It will also cache all records anytime someone runs `dns me lookup`.

## RBAC
Creating and deleting entries requires a user to have the role of `dns_admin`. Yes this is hardcoded for now. Additionally, a `dns_admin` will be able to restrict the max number of results returned from audit logging queries.

## Audit logging
Hubot will store any creates/updates/deletes in its internal audit log. you can get to this two ways:

`hubot dns me log <count>` where count is either `max` or a number of entries. The max entries can be increased via `dns me max results <N>` from a user with the `dns_admin` role.
or
`hubot dns me last <count> <action>` where count is as described above and `action` is one of `create` or `delete`

The results are returned with newest first and look like so:

```
DELETE | 902682 | 14080170 | lusis | A | 192.168.1.1 | Shell | 1h ago
CREATE | 902682 | 14080170 | lusis | A | 192.168.1.1 | Shell | 1h ago
DELETE | 902682 | 14079756 | lusis | A | 192.168.1.1 | Shell | 2h ago
CREATE | 902682 | 14079756 | lusis | A | 192.168.1.1 | Shell | 2h ago
```
The columes are: `ACTION|DOMAIN ID|RECORD ID|NAME|RECORD TYPE|VALUE|RELATIVE TIME|`

## Sparklines
This is really just for fun but the DME2 API allows you to return the number of queries against all of your domains. This is just a bit of fun on top of that.

```
Hubot> hubot dns me stats
Hubot> ▂▃▅▇▆▆▅▆▅▆▆▆▁
```

## Note on delete
Delete operations depend on an up to date internal cache. Currently the only way to refresh that cache is via a lookup.
The intention here is that a lookup should be REQUIRED before a delete can happen because delete operations require the record id:

`hubot dns me delete mydomain.com 123456`

For now, before deleting simply perform a lookup first:

```
hubot dns me lookup foo mydomain.com
> foo | A | X.X.X.X | 10405367
```

The last column is the id you'll need.

# TODO
- Logging is insane. Most useful information is returned at INFO but if you're running with debug, you're gonna have a bad time. The debugs REALLY need to be cleaned up.
- I didn't know coffeescript before I started this project. It shows. A lot.
- Need to add support for updating entries instead of just create and delete
- Need more safeguards around root entries. Currently when a root entry (such as a `SOA` or `MX` record is returns, the data is cached with a key of the domain name itself.
- Cache purging/refreshing
- Probably a lot of things

# Pull requests
- Fork it
- Create a new branch
- Change some things
- Make a pull request
- Be happy
- Use sunblock
- Don't eat yellow snow
