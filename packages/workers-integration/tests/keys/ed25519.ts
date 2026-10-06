import { parsePrivateKey, PrivateKey } from "sshpk"

export const privateKeyString = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDFbUIeQIJ5vZ5Jz9vXLnVCyXNhXadKJOubbov/hifMfwAAAIhKaQBeSmkA
XgAAAAtzc2gtZWQyNTUxOQAAACDFbUIeQIJ5vZ5Jz9vXLnVCyXNhXadKJOubbov/hifMfw
AAAED8pydCkvNrysAmDUbVnT5goaFlepU9kjmIyP/O5G9HOMVtQh5Agnm9nknP29cudULJ
c2Fdp0ok65tui/+GJ8x/AAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----
`

export const privateKey = (): PrivateKey => {
    return parsePrivateKey(privateKeyString)
}

const userPrivateKeyString = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACD2AT6rFE1c/74j2kuUm0kNa4Ci6u24/X2Fi7lF5r7GhwAAAJhhwQZzYcEG
cwAAAAtzc2gtZWQyNTUxOQAAACD2AT6rFE1c/74j2kuUm0kNa4Ci6u24/X2Fi7lF5r7Ghw
AAAEBZSdSCVLwRGns5o2KD2r9aDHIpYBF+j9ceR3yn3cMzV/YBPqsUTVz/viPaS5SbSQ1r
gKLq7bj9fYWLuUXmvsaHAAAAEHVzZXJAZXhhbXBsZS5jb20BAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
`

export const userPrivateKey = (): PrivateKey => {
    return parsePrivateKey(userPrivateKeyString)
}

// a CA key whose seed starts with 0x00 followed by a byte below 0x80, which
// sshpk writes to PKCS#8 with the leading zero dropped
export const leadingZeroPrivateKeyString = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCID/KNdIMcAOAkNTKYgXBmzI3Fz2Z7N1+Ea8AmcRHK7wAAAIi7BqbYuwam
2AAAAAtzc2gtZWQyNTUxOQAAACCID/KNdIMcAOAkNTKYgXBmzI3Fz2Z7N1+Ea8AmcRHK7w
AAAEAAPuqDE5ftCR+/QfVH5xhX8nyuNV2sKzm1vaP6oPAwyIgP8o10gxwA4CQ1MpiBcGbM
jcXPZns3X4RrwCZxEcrvAAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----
`
