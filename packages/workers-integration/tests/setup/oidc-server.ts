import { createServer } from "node:http"
import { generateKeyPairSync, createSign, createPublicKey } from "node:crypto"

// Generate RS256 keypair at startup
const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "der" },
})

const port = parseInt(process.env.OIDC_PORT ?? "4567")
const aud = process.env.JWT_AUD ?? "audience"

// Convert DER public key to JWK
const publicKeyObj = createPublicKey({ key: publicKey, format: "der", type: "spki" })
const jwk = publicKeyObj.export({ format: "jwk" })

const makeJwt = (claims: Record<string, unknown>): string => {
    const header = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString("base64url")
    const payload = Buffer.from(JSON.stringify({
        iss: `http://localhost:${port}`,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
		...(aud ? { aud } : {}),
        ...claims,
    })).toString("base64url")

    const data = `${header}.${payload}`
    const sign = createSign("RSA-SHA256")
    sign.update(data)
    const sig = sign.sign({ key: privateKey, format: "der", type: "pkcs8" }).toString("base64url")

    return `${data}.${sig}`
}

export const setup = async () => {
    const server = createServer((req, res) => {
        if (req.method === "GET" && req.url === "/jwks") {
            res.writeHead(200, { "Content-Type": "application/json" })
            res.end(JSON.stringify({
                keys: [{ ...jwk, use: "sig", alg: "RS256", kid: "test-key" }]
            }))
            return
        }

        if (req.method === "POST" && req.url === "/token") {
            let body = ""
            req.on("data", chunk => { body += chunk })
            req.on("end", () => {
                try {
                    const { claims } = JSON.parse(body) as { claims: Record<string, unknown> }
                    const token = makeJwt(claims)
                    res.writeHead(200, { "Content-Type": "application/json" })
                    res.end(JSON.stringify({ token }))
                } catch {
                    res.writeHead(400)
                    res.end()
                }
            })
            return
        }

        res.writeHead(404)
        res.end()
    })

    await new Promise<void>(resolve => server.listen(port, resolve))
    console.log(`OIDC mock server listening on http://localhost:${port}`)

    return () => new Promise<void>((resolve, reject) =>
        server.close(err => err ? reject(err) : resolve())
    )
}
