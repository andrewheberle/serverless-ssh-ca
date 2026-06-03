

export class MockSecretStore {
    private readonly privateKeyString: string
    
    constructor(key: string) {
        this.privateKeyString = key
    }

    async get(): Promise<string> {
        return this.privateKeyString
    }
}