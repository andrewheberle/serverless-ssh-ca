import { describe, it, expect } from "vitest"
import { identityPrincipals, split } from "../src/utils"
import { env } from "./env"

describe("split", () => {
    it ("with empty string", () => {
        const result = split("")
        expect(result).toStrictEqual([])
    })

    it ("one value", () => {
        const result = split("first")
        expect(result).toStrictEqual(["first"])
    })

    it ("two values", () => {
        const result = split("first,second")
        expect(result).toStrictEqual(["first", "second"])
    })
})

describe("identityPrincipals", () => {
    it ("no principals claim", () => {
        const result = identityPrincipals(env, {email: "user@example.com", sub: "user"})
        expect(result).toStrictEqual([])
    })

    it ("empty string principals claim", () => {
        const result = identityPrincipals(env, {email: "user@example.com", sub: "user", groups: ""}, "groups")
        expect(result).toStrictEqual([])
    })

    it ("empty array principals claim", () => {
        const result = identityPrincipals(env, {email: "user@example.com", sub: "user", groups: []}, "groups")
        expect(result).toStrictEqual([])
    })

    it ("principals claim as string", () => {
        const result = identityPrincipals(env, {email: "user@example.com", sub: "user", groups: "foo"}, "groups")
        expect(result).toStrictEqual(["foo"])
    })

    it ("principals claim as array", () => {
        const result = identityPrincipals(env, {email: "user@example.com", sub: "user", groups: ["foo"]}, "groups")
        expect(result).toStrictEqual(["foo"])
    })

    it ("principals claim as array with two items", () => {
        const result = identityPrincipals(env, {email: "user@example.com", sub: "user", groups: ["foo", "bar"]}, "groups")
        expect(result).toStrictEqual(["foo", "bar"])
    })
})
