# iran_ban_resolver
iran_ban_resolver is a coredns plugin to that resolves banned domains from trusted DNS servers(like Shekan and Electro) to their real IPs.

## config
example:
```
iran_ban_resolver {
        reload 500ms
        hosts ./hosts_dir/hosts-ban
        resolve-from 78.157.42.101:53
    }
```