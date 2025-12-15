import { describe, it, expect } from "vitest"
import { split } from "../src/utils"

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