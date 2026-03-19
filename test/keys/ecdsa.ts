import { parsePrivateKey, PrivateKey } from "sshpk"

const privateKeyString = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQTrh5Brsk2pEY/l1HUv9iB633qsuPzf
GxVbZUi7LXKitJua4v4mZEpuQfCGXa2ZYJtIIDXm+m3YdLkbAYBElWcSAAAAwBqUjmkalI
5pAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOuHkGuyTakRj+XU
dS/2IHrfeqy4/N8bFVtlSLstcqK0m5ri/iZkSm5B8IZdrZlgm0ggNeb6bdh0uRsBgESVZx
IAAAAgenwTB1kprsmfs3e2PWGfZ4JDi+d5PTEMg6Rf3WgLZ+sAAAAmci1ncm91cFxhbmRy
ZXcuaGViZXJsZUBSR0ktVEo5OUY5aEpqeFUBAg==
-----END OPENSSH PRIVATE KEY-----`

export const privateKey = (): PrivateKey => {
    return parsePrivateKey(privateKeyString)
}

const userPrivateKeyString = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQRjKUibbX9CLbTQlXNvE81xUdQ9Mbzt
56eu1c3gELG3WbJKw3GI0pcCehzw5k6V2lNJRGl/S+GIXP3An9THvRU5AAAAwG2j6Ixto+
iMAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGMpSJttf0IttNCV
c28TzXFR1D0xvO3np67VzeAQsbdZskrDcYjSlwJ6HPDmTpXaU0lEaX9L4Yhc/cCf1Me9FT
kAAAAhAIylYk8XpB+vvhmQRlWBc0ptx5C8p90ONWJyUU47gok+AAAAJnItZ3JvdXBcYW5k
cmV3LmhlYmVybGVAUkdJLVRKOTlGOWhKanhVAQ==
-----END OPENSSH PRIVATE KEY-----`

export const userPrivateKey = (): PrivateKey => {
    return parsePrivateKey(userPrivateKeyString)
}