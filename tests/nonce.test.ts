import { describe, it, expect } from "vitest"
import { Nonce } from "../src/nonce"
import { Key, parseKey } from "sshpk"

type testSig = {
    name: string
    sig: string
    data: string
    from: number
    want: boolean
    wantErr?: string
    matches?: string[]
    wantMatches?: boolean
}

const tests: testSig[] = [
    {
        name: "RSA key should parse and verify",
        sig: "LS0tLS1CRUdJTiBTU0ggU0lHTkFUVVJFLS0tLS0KVTFOSVUwbEhBQUFBQVFBQUFaY0FBQUFIYzNOb0xYSnpZUUFBQUFNQkFBRUFBQUdCQU1yMHJUQno3S1RydlZ3TQpNZDFkaFZnZUl3UFJIUng3OVFvWVZ1Z09COWo0ZytKYnNaWEtKRTFiWFo2MEpnYlRHb2p2T2QyV0ROcTRuQVdqCktWa2VTS1UxeUNFK29TS1pSYm9qZit3dHF0ZWVMYzVGZ0NDUXZBWFVTcnJkTEdobzU2VUw1eFNQNkx1OHFzdTYKeG51ZkZkaWJ1cGhhaUtFV2xFQTJsWnF2b2htdTdIUTBPZUFWRTZiRWNoWm5zeFBXVzErTXA0a05saEI1QkdJcgpDMFlNTkR4QnZ5N0F6RWk3K0FRR1hvaUZRTVJCK2hiSCtGZU5kQ2lVWmV0SmNQRWJwc1pqUENFRENUVFpoaFZMCmtYellxc0tEOFBOWEd2VG9rN2dWUmpTSnEyQmU0RGFMOXlNUmF5K2pjZnRvOFFNQjIwVDMzZWlHdmVuQTl2Qk0KNysyb2dISU0yTkJ6M3V5VnVmUTViYjdVTTdwZUlocE5jaWRUeUg1VWhsaHZ1NnJaaU9yWjM1T0VaaERpc3A2WQpycDBHRUZ0SUREZHBCSXg0ZzgxN0JUK3BnV00rM0E3bndUWFpaeXZ4TTU2SlFXUGJyeklHeWlyRElibkxsRCsvCmVnWFBMMlNQZVhzTlk1VDA2K0o1T3pWU3dqYzhjRlhtbndWT25XZVJQRlRLc2oxdExRQUFBQVJtYVd4bEFBQUEKQUFBQUFBWnphR0UxTVRJQUFBR1VBQUFBREhKellTMXphR0V5TFRVeE1nQUFBWUNZU09WdWhNa1BHNGNZN3lqTgpWTEZvc0hHRFR1SENqUWluMk9BcUhDWjR5R2NxbEo3WUJ1YVpqVWU3RWRSM0RENU43bFgyc2JnZGhBTlV2NkdBCkE5VWFGTHJlWjVORmhMSlhDbk1RbkdpTEZKSEViR0taZnNvUVA0Y1cvSDdXSHFnWUFFbUtwYUdmdm9iNHRDR1oKZ1RJWUZEWVVrdE9qd3p3UEFpNlhRV0VIZW9XQ3YwWDVpSjBMd0xUZVQ0WE9MWXFNQmlQNzlOdFN3L2pBUlZFaAprTEppa05xc2tMT2paaXBXR2xmcTZBQlg4SFBsYjVnSFBDaGJ5TElmd3lhRFd2a0Zja1d5V1BNZk43U1pQWG04ClpPTGwwZGpvY213RGVpeVdYcWFHTG9JWFhNN01SQWoyRmZIeGpITWtsS0FYWFlCTjMvcktMR2xQSEdQeXR4UnIKMi85OTFFd2pId3hlaVlrVFVTT0ZzVW1PU2hBQW9tY3NuclFBWmYvOVpwNEI0M0tHVnlUWHJZd1JRYlprVU52SQpSZTg1NkZaYlRwaVFmMEthRUpGditlWEtEeDJ4a29qMUkyLzRMMitYZ1h4VEl4SG9oOE5ITll5dmw3WmhzQVlBCjVTVlpaV01Yd2hDenNiMlpucHZCTXR4VFovZk1CNWNWRDQ3OXlsa0RoYXl6YVlzPQotLS0tLUVORCBTU0ggU0lHTkFUVVJFLS0tLS0K",
        data: "1765696780805.SHA256:pKEDCHTFD39a8fmusevX8Hob8p9sZVERd8yqGyLpR/A",
        from: 1765696780000,
        want: true
    },
    {
        name: "ECDSA key should parse and verify",
        sig: "LS0tLS1CRUdJTiBTU0ggU0lHTkFUVVJFLS0tLS0KVTFOSVUwbEhBQUFBQVFBQUFHZ0FBQUFUWldOa2MyRXRjMmhoTWkxdWFYTjBjREkxTmdBQUFBaHVhWE4wY0RJMQpOZ0FBQUVFRUR6Ymk4OE10alBYSDFCb1JURU9HaS96aEc4QnhQNVZUUW5OQkFNMGZtMExtekErUUZkUlNVYVRFCkdNN2l0QjhINmZNZFAydlAxcElQcGUyOWVLQkJZd0FBQUFSbWFXeGxBQUFBQUFBQUFBWnphR0UxTVRJQUFBQmsKQUFBQUUyVmpaSE5oTFhOb1lUSXRibWx6ZEhBeU5UWUFBQUJKQUFBQUlHdmZVZGNDQkRXa3ZwL0ZHS3NkakgrRQpKZzZXN0EvWUJVZng2Z0srQ01raEFBQUFJUUQxOFd5cDNZejZ0eXNvdllXbEJHTXprRnlYbFRrSHM5blVVRXJqCkczNWVPQT09Ci0tLS0tRU5EIFNTSCBTSUdOQVRVUkUtLS0tLQo=",
        data: "1765696780805.SHA256:79mq0wtpQMTvS4+Of8VzLN0qmYWNUyTXYmqKwhEgSLs",
        from: 1765696780000,
        want: true
    },
    {
        name: "ED25519 key should parse and verify",
        sig: "LS0tLS1CRUdJTiBTU0ggU0lHTkFUVVJFLS0tLS0KVTFOSVUwbEhBQUFBQVFBQUFETUFBQUFMYzNOb0xXVmtNalUxTVRrQUFBQWdselE4SWpOeHVLMG0wOGdBcHdUUgpMUkVxUlFOSnVYZGRMek1OWHh2OUZ3WUFBQUFFWm1sc1pRQUFBQUFBQUFBR2MyaGhOVEV5QUFBQVV3QUFBQXR6CmMyZ3RaV1F5TlRVeE9RQUFBRUFRd0RKRWowNzRnekYyT2k4NkRUbllGV1BmZGc1aVQxWnRTaXoxdWYxQ0k1anAKVVVORU56b09iVmJmNjZsRlFac3hBRS9OMm5yWXJjTTQrQWNMQm80TgotLS0tLUVORCBTU0ggU0lHTkFUVVJFLS0tLS0K",
        data: "1765696780805.SHA256:4A33TPWJZ8trpUhhn0mpK1wISFzVGhWlWShoGylLUbg",
        from: 1765696780000,
        want: true
    },
    {
        name: "should error due to old timestamp",
        sig: "LS0tLS1CRUdJTiBTU0ggU0lHTkFUVVJFLS0tLS0KVTFOSVUwbEhBQUFBQVFBQUFETUFBQUFMYzNOb0xXVmtNalUxTVRrQUFBQWdselE4SWpOeHVLMG0wOGdBcHdUUgpMUkVxUlFOSnVYZGRMek1OWHh2OUZ3WUFBQUFFWm1sc1pRQUFBQUFBQUFBR2MyaGhOVEV5QUFBQVV3QUFBQXR6CmMyZ3RaV1F5TlRVeE9RQUFBRUFRd0RKRWowNzRnekYyT2k4NkRUbllGV1BmZGc1aVQxWnRTaXoxdWYxQ0k1anAKVVVORU56b09iVmJmNjZsRlFac3hBRS9OMm5yWXJjTTQrQWNMQm80TgotLS0tLUVORCBTU0ggU0lHTkFUVVJFLS0tLS0K",
        data: "1765696780805.SHA256:4A33TPWJZ8trpUhhn0mpK1wISFzVGhWlWShoGylLUbg",
        from: 1765699990000,
        wantErr: "nonce timestamp too old",
        want: false
    },
    {
        name: "should error due to bad timestamp",
        sig: "LS0tLS1CRUdJTiBTU0ggU0lHTkFUVVJFLS0tLS0KVTFOSVUwbEhBQUFBQVFBQUFETUFBQUFMYzNOb0xXVmtNalUxTVRrQUFBQWdselE4SWpOeHVLMG0wOGdBcHdUUgpMUkVxUlFOSnVYZGRMek1OWHh2OUZ3WUFBQUFFWm1sc1pRQUFBQUFBQUFBR2MyaGhOVEV5QUFBQVV3QUFBQXR6CmMyZ3RaV1F5TlRVeE9RQUFBRUFRd0RKRWowNzRnekYyT2k4NkRUbllGV1BmZGc1aVQxWnRTaXoxdWYxQ0k1anAKVVVORU56b09iVmJmNjZsRlFac3hBRS9OMm5yWXJjTTQrQWNMQm80TgotLS0tLUVORCBTU0ggU0lHTkFUVVJFLS0tLS0K",
        data: "invalid.SHA256:4A33TPWJZ8trpUhhn0mpK1wISFzVGhWlWShoGylLUbg",
        from: 1765696780000,
        wantErr: "timestamp was not a number",
        want: true
    },
    {
        name: "should error due to extra data",
        sig: "LS0tLS1CRUdJTiBTU0ggU0lHTkFUVVJFLS0tLS0KVTFOSVUwbEhBQUFBQVFBQUFETUFBQUFMYzNOb0xXVmtNalUxTVRrQUFBQWdselE4SWpOeHVLMG0wOGdBcHdUUgpMUkVxUlFOSnVYZGRMek1OWHh2OUZ3WUFBQUFFWm1sc1pRQUFBQUFBQUFBR2MyaGhOVEV5QUFBQVV3QUFBQXR6CmMyZ3RaV1F5TlRVeE9RQUFBRUFRd0RKRWowNzRnekYyT2k4NkRUbllGV1BmZGc1aVQxWnRTaXoxdWYxQ0k1anAKVVVORU56b09iVmJmNjZsRlFac3hBRS9OMm5yWXJjTTQrQWNMQm80TgotLS0tLUVORCBTU0ggU0lHTkFUVVJFLS0tLS0K",
        data: "1765696780805.SHA256:4A33TPWJZ8trpUhhn0mpK1wISFzVGhWlWShoGylLUbg.extra",
        from: 1765696780000,
        wantErr: "invalid nonce format",
        want: true
    },
    {
        name: "should error due to invalid fingerprint",
        sig: "LS0tLS1CRUdJTiBTU0ggU0lHTkFUVVJFLS0tLS0KVTFOSVUwbEhBQUFBQVFBQUFETUFBQUFMYzNOb0xXVmtNalUxTVRrQUFBQWdselE4SWpOeHVLMG0wOGdBcHdUUgpMUkVxUlFOSnVYZGRMek1OWHh2OUZ3WUFBQUFFWm1sc1pRQUFBQUFBQUFBR2MyaGhOVEV5QUFBQVV3QUFBQXR6CmMyZ3RaV1F5TlRVeE9RQUFBRUFRd0RKRWowNzRnekYyT2k4NkRUbllGV1BmZGc1aVQxWnRTaXoxdWYxQ0k1anAKVVVORU56b09iVmJmNjZsRlFac3hBRS9OMm5yWXJjTTQrQWNMQm80TgotLS0tLUVORCBTU0ggU0lHTkFUVVJFLS0tLS0K",
        data: "1765696780805.invalid",
        from: 1765696780000,
        wantErr: "nonce fingerprint was an invalid format",
        want: true
    },
    {
        name: "should fail verify due to bad signature",
        sig: "invalid",
        data: "1765696780805.SHA256:4A33TPWJZ8trpUhhn0mpK1wISFzVGhWlWShoGylLUbg",
        from: 1765696780000,
        wantErr: "nonce signature could not be parsed",
        want: false
    },
]

describe("Nonce", async () => {
    const timestamp = 1765696780805

    for (const tt of tests) {
        it(tt.name, async () => {
            if (tt.wantErr !== undefined) {
                expect(() => new Nonce(`${tt.data}.${tt.sig}`, tt.from))
                    .toThrow(tt.wantErr)
            } else {
                const nonce = new Nonce(`${tt.data}.${tt.sig}`, tt.from)

                // verify timestamp and signature
                expect(nonce.timestamp).toBe(timestamp)
                expect(await nonce.verify()).toBe(tt.want)

                // check matches for keys
                if (tt.matches !== undefined) {
                    const keys = tt.matches.map((k: string): Key => {
                        return parseKey(k)
                    })

                    expect(nonce.matches(...keys)).toBe(tt.wantMatches !== undefined ? tt.wantMatches : false)
                }
            }
        })
    }

})
