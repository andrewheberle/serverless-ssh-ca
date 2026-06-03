import { parsePrivateKey, type PrivateKey } from "sshpk"

export const caKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDFbUIeQIJ5vZ5Jz9vXLnVCyXNhXadKJOubbov/hifMfwAAAIhKaQBeSmkA
XgAAAAtzc2gtZWQyNTUxOQAAACDFbUIeQIJ5vZ5Jz9vXLnVCyXNhXadKJOubbov/hifMfw
AAAED8pydCkvNrysAmDUbVnT5goaFlepU9kjmIyP/O5G9HOMVtQh5Agnm9nknP29cudULJ
c2Fdp0ok65tui/+GJ8x/AAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----
`

const userKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACD2AT6rFE1c/74j2kuUm0kNa4Ci6u24/X2Fi7lF5r7GhwAAAJhhwQZzYcEG
cwAAAAtzc2gtZWQyNTUxOQAAACD2AT6rFE1c/74j2kuUm0kNa4Ci6u24/X2Fi7lF5r7Ghw
AAAEBZSdSCVLwRGns5o2KD2r9aDHIpYBF+j9ceR3yn3cMzV/YBPqsUTVz/viPaS5SbSQ1r
gKLq7bj9fYWLuUXmvsaHAAAAEHVzZXJAZXhhbXBsZS5jb20BAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
`

const hostKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCbYgZkXuuIbJWuSLROEmeaN36DqvcYpWsVCLtUc9z8wwAAAIh4yTTDeMk0
wwAAAAtzc2gtZWQyNTUxOQAAACCbYgZkXuuIbJWuSLROEmeaN36DqvcYpWsVCLtUc9z8ww
AAAEAUa972+l6etRZUgUGZ0sMeoimezSoKHPh/Agektd/kHZtiBmRe64hsla5ItE4SZ5o3
foOq9xilaxUIu1Rz3PzDAAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----
`

export const key = {
    ca(): PrivateKey {
        return parsePrivateKey(caKey)
    },
    host(): PrivateKey {
        return parsePrivateKey(hostKey)
    },
    user(): PrivateKey {
        return parsePrivateKey(userKey)
    },

}
