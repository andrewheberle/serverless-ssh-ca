import type { CaSecret } from "../../src/types.js"

export class MockSecretStore implements CaSecret {
    private readonly privateKeyString: string
    
    constructor(key: string) {
        this.privateKeyString = key
    }

    async get(): Promise<string> {
        return this.privateKeyString
    }
}