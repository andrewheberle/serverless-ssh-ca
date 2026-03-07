import { SELF } from "cloudflare:test"
import { describe, it, expect } from "vitest"

describe("get /404", () => {
    it ("responds with a 404", async () => {
        const response = await SELF.fetch("http://example.com/404")
        expect(response.status).toBe(404)
    })
})

describe("get /docs", () => {
    it ("responds with a 200", async () => {
        const response = await SELF.fetch("http://example.com/docs")
        expect(response.status).toBe(200)
    })
})

describe("get /api/v2/ca", () => {
    it ("responds with a 200", async () => {
        const response = await SELF.fetch("http://example.com/api/v2/ca")
        expect(response.status).toBe(200)
    })
})
