## Chrome Password/Cookie Dumper for OSX

This package is for Dump Cookie /Login  Password  from Google Chrome (Mac OSX )

Since Chrome 45 , Google unsupport OSX Keychain sync.

So, we must import IDs manually....

## Usage

#### Dump cookie
```
./bin/chrome-cookie www.yahoo.co.jp | jq .
```

#### Dump id/pass
```sh
./bin/chrome-login-data www.yahoo.co.jp | jq .
```

## How to import to OSX keychain 

You can impart dumped ID/Password to your OSX Keychain.app .

Use osx bundled ``security``  commands to import like This.

```sh
security add-internet-password -a USER_NAME -s HOST -w PASSWORD -j COMMENT  -p URI  -U
```


### Enjoy !
