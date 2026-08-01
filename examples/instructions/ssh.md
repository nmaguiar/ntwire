## Connect with SSH

This tunnel forwards to `{{.TargetHint}}`. Once `ntwire connect` is running,
connect through it with:

```sh
ssh -p {{.LocalPort}} youruser@{{.LocalHost}}
```

**Optional:** add a matching entry to `~/.ssh/config` so `ssh {{.Name}}` works
without typing the port:

```
Host {{.Name}}
    HostName {{.LocalHost}}
    Port {{.LocalPort}}
    User youruser
```

Always use the port shown here rather than the one in the server's
`local_port` setting: that value is only a preference, an occupied port falls
back to a free one, and `{{.LocalPort}}` reflects whatever `ntwire connect`
actually bound this run.

### Copying files

The same port works with `scp` and `rsync` over SSH:

```sh
scp -P {{.LocalPort}} youruser@{{.LocalHost}}:/remote/path ./local-path
rsync -e "ssh -p {{.LocalPort}}" -av youruser@{{.LocalHost}}:/remote/path/ ./local-path/
```
