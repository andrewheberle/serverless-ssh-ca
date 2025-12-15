import { parsePrivateKey, PrivateKey } from "sshpk"

const privateKeyString = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDFbUIeQIJ5vZ5Jz9vXLnVCyXNhXadKJOubbov/hifMfwAAALAmIff2JiH3
9gAAAAtzc2gtZWQyNTUxOQAAACDFbUIeQIJ5vZ5Jz9vXLnVCyXNhXadKJOubbov/hifMfw
AAAED8pydCkvNrysAmDUbVnT5goaFlepU9kjmIyP/O5G9HOMVtQh5Agnm9nknP29cudULJ
c2Fdp0ok65tui/+GJ8x/AAAAJnItZ3JvdXBcYW5kcmV3LmhlYmVybGVAUkdJLVRKOTlGOW
hKanhVAQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----`

export const privateKey = (): PrivateKey => {
    return parsePrivateKey(privateKeyString)
}

const userPrivateKeyString = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACD2AT6rFE1c/74j2kuUm0kNa4Ci6u24/X2Fi7lF5r7GhwAAALDrQY1e60GN
XgAAAAtzc2gtZWQyNTUxOQAAACD2AT6rFE1c/74j2kuUm0kNa4Ci6u24/X2Fi7lF5r7Ghw
AAAEBZSdSCVLwRGns5o2KD2r9aDHIpYBF+j9ceR3yn3cMzV/YBPqsUTVz/viPaS5SbSQ1r
gKLq7bj9fYWLuUXmvsaHAAAAJnItZ3JvdXBcYW5kcmV3LmhlYmVybGVAUkdJLVRKOTlGOW
hKanhVAQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----`

export const userPrivateKey = (): PrivateKey => {
    return parsePrivateKey(userPrivateKeyString)
}