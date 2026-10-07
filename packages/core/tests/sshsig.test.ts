import { describe, it, expect } from "vitest"
import { generatePrivateKey } from "sshpk"
import { verify } from "../src/sshsig/index.js"
import { parse, ecdsaComponentSize, toFixedWidth } from "../src/sshsig/sig_parser.js"
import { Namespace, ProofOfPossession } from "../src/proof.js"
import { generateProof } from "./helpers/proof.js"

type fixture = {
	name: string
	size: number
	data: string
	signature: string
}

// signatures produced by ssh-keygen -Y sign where r or s encodes to fewer
// bytes than the curve size, so must be left-padded before verification.
// every nistp521 signature needs converting as its components are 66 bytes
const fixtures: fixture[] = [
	{
		name: "nistp256 short r",
		size: 32,
		data: "1791273145535.SHA256:TyRab7RatZE4IcxnTe0GX7biG8olcfiImNYMN1mPvZs",
		signature: `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAAGgAAAATZWNkc2Etc2hhMi1uaXN0cDI1NgAAAAhuaXN0cDI1NgAAAE
EEF9zt4nPIaInULb8tiNt5LQmBZx8pZgeS0DN4M9wDP6KH6KrYathVG0ZxZF1h9CyRktve
ieBAXUi/Lio1CosVLAAAAD5wcm9vZi1vZi1wb3NzZXNzaW9uQGNvbS5naXRodWIuc2Vydm
VybGVzcy1zc2gtY2EuYW5kcmV3aGViZXJsZQAAAAAAAAAGc2hhNTEyAAAAYgAAABNlY2Rz
YS1zaGEyLW5pc3RwMjU2AAAARwAAAB8DU5E48gpmMkzhGgAEjzh9lN2l0xBo32YT/958uS
toAAAAIG0LfFEc0Da/2qhDCuRo38WLTNls1D3QAxEwAXv1ksAU
-----END SSH SIGNATURE-----`,
	},
	{
		name: "nistp256 short s",
		size: 32,
		data: "1791273143266.SHA256:TyRab7RatZE4IcxnTe0GX7biG8olcfiImNYMN1mPvZs",
		signature: `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAAGgAAAATZWNkc2Etc2hhMi1uaXN0cDI1NgAAAAhuaXN0cDI1NgAAAE
EEF9zt4nPIaInULb8tiNt5LQmBZx8pZgeS0DN4M9wDP6KH6KrYathVG0ZxZF1h9CyRktve
ieBAXUi/Lio1CosVLAAAAD5wcm9vZi1vZi1wb3NzZXNzaW9uQGNvbS5naXRodWIuc2Vydm
VybGVzcy1zc2gtY2EuYW5kcmV3aGViZXJsZQAAAAAAAAAGc2hhNTEyAAAAYwAAABNlY2Rz
YS1zaGEyLW5pc3RwMjU2AAAASAAAACEA089nyT4g79RqM3NhMJu0o6SX8v5pL7uQQSWnDf
mWnqMAAAAfHJV59fqTYhpKxs4R98l3eAsy6amaHUG45WKQLt0N8A==
-----END SSH SIGNATURE-----`,
	},
	{
		name: "nistp384 short r",
		size: 48,
		data: "1791273167785.SHA256:FQ9KEhbsAIVAyTGJ5Qm0Sdq9Uagc4lSSJ6vbR00OEi4",
		signature: `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAAIgAAAATZWNkc2Etc2hhMi1uaXN0cDM4NAAAAAhuaXN0cDM4NAAAAG
EEOiUvbYuq2ybpLqUp7T6ijCFwqqUJD0lUuvnG7GOFMCMlYnxQRqAzeaUkLhC4q3IR4VU0
az96W6bgHvTAlAKjdb5G8m2gVew783Yoh0+9GSI8TK5EGURVh4fo34Jl7LnAAAAAPnByb2
9mLW9mLXBvc3Nlc3Npb25AY29tLmdpdGh1Yi5zZXJ2ZXJsZXNzLXNzaC1jYS5hbmRyZXdo
ZWJlcmxlAAAAAAAAAAZzaGE1MTIAAACDAAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAABoAA
AALwybkQ81EH0Nf85V7N99RfDMZ+BwyAvTZcIgbUZrAoTWuzH3JM/p9sLuXhvcmzbjAAAA
MQDu6X4Hwus0Ehm5d1OOxryz1Dlx85ONVsPm5QkF0A8WVY3tBJC/p4g8yYafAKxfpN8=
-----END SSH SIGNATURE-----`,
	},
	{
		name: "nistp384 short s",
		size: 48,
		data: "1791273158930.SHA256:FQ9KEhbsAIVAyTGJ5Qm0Sdq9Uagc4lSSJ6vbR00OEi4",
		signature: `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAAIgAAAATZWNkc2Etc2hhMi1uaXN0cDM4NAAAAAhuaXN0cDM4NAAAAG
EEOiUvbYuq2ybpLqUp7T6ijCFwqqUJD0lUuvnG7GOFMCMlYnxQRqAzeaUkLhC4q3IR4VU0
az96W6bgHvTAlAKjdb5G8m2gVew783Yoh0+9GSI8TK5EGURVh4fo34Jl7LnAAAAAPnByb2
9mLW9mLXBvc3Nlc3Npb25AY29tLmdpdGh1Yi5zZXJ2ZXJsZXNzLXNzaC1jYS5hbmRyZXdo
ZWJlcmxlAAAAAAAAAAZzaGE1MTIAAACCAAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAABnAA
AAMDAofbUAXmvg06siKbC0WDubB9+yAjoUwPVSK4aFObsaMCRGxGCDHYFVpPDib1t0AwAA
AC96GIssPp4ITYZybKuR5cUivgUPx+QkXraOC4yy7IJz9DHwiEGY3w7+AFnRODYbYw==
-----END SSH SIGNATURE-----`,
	},
	{
		name: "nistp521 short r",
		size: 66,
		data: "1791273045999.SHA256:Ud4EdeP1ZTdM8YTwIpRh4+lSA7VMNQhmM5gFKMAI5Gc",
		signature: `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAAKwAAAATZWNkc2Etc2hhMi1uaXN0cDUyMQAAAAhuaXN0cDUyMQAAAI
UEAKeVy/O5I4n6pbXbxIPfTEMuFxEm/5xEn3pIC42Zvw8mJmL8M2jjU1z2ev10UGGul3I8
MKV+amb9iY/RZERoWJRyAAZADXkGS0eXLIY/eArbZUdGA3tqO7H3zaX49eo+OpGIrLMj/+
kNX4gxcx4rHQEsz59VOF+OpM6Zj4eRH/rw3nUBAAAAPnByb29mLW9mLXBvc3Nlc3Npb25A
Y29tLmdpdGh1Yi5zZXJ2ZXJsZXNzLXNzaC1jYS5hbmRyZXdoZWJlcmxlAAAAAAAAAAZzaG
E1MTIAAACnAAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAACMAAAAQgD4SDjefHdBbtM/h9IK
UTy821iRu25BNTdF6PWDfdmuBJ5aT0i4fY5GlpiN8uonsm4AH79DhDDQUWn16UyhJUxVEw
AAAEIBCYy2YdEsznsERudDtlwdcI/VeHztP0EEAdWqKP/+1Ud3v71Www3MhW1BdzymsMMG
NM8DdlviN71bIS8XRxrPM6s=
-----END SSH SIGNATURE-----`,
	},
	{
		name: "nistp521 short s",
		size: 66,
		data: "1791273045944.SHA256:Ud4EdeP1ZTdM8YTwIpRh4+lSA7VMNQhmM5gFKMAI5Gc",
		signature: `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAAKwAAAATZWNkc2Etc2hhMi1uaXN0cDUyMQAAAAhuaXN0cDUyMQAAAI
UEAKeVy/O5I4n6pbXbxIPfTEMuFxEm/5xEn3pIC42Zvw8mJmL8M2jjU1z2ev10UGGul3I8
MKV+amb9iY/RZERoWJRyAAZADXkGS0eXLIY/eArbZUdGA3tqO7H3zaX49eo+OpGIrLMj/+
kNX4gxcx4rHQEsz59VOF+OpM6Zj4eRH/rw3nUBAAAAPnByb29mLW9mLXBvc3Nlc3Npb25A
Y29tLmdpdGh1Yi5zZXJ2ZXJsZXNzLXNzaC1jYS5hbmRyZXdoZWJlcmxlAAAAAAAAAAZzaG
E1MTIAAACnAAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAACMAAAAQgGS+SSoJKlRwruQCBby
RvtHHCCaMAQvOzlaoibZ5YN6mZAju44UfAMRoJZ2FI5nPAlGdJbHrbfNx+po1Lcj7burvQ
AAAEIA+tY8mJp0jwkGNM4fER58/EQJzTUK4CGwTj5xTXxKtSwjWH3CXw2LqFyUCkIEAmVE
w76ltZtXHyRboJA2b2iBtws=
-----END SSH SIGNATURE-----`,
	},
]

describe("toFixedWidth", () => {
	it("should left-pad a short value", () => {
		expect(toFixedWidth(new Uint8Array([0x01, 0x02]), 4)).toEqual(new Uint8Array([0x00, 0x00, 0x01, 0x02]))
	})

	it("should strip a leading zero added for the sign bit", () => {
		expect(toFixedWidth(new Uint8Array([0x00, 0x80, 0x01, 0x02, 0x03]), 4)).toEqual(new Uint8Array([0x80, 0x01, 0x02, 0x03]))
	})

	it("should strip a leading zero and pad when the value is also short", () => {
		expect(toFixedWidth(new Uint8Array([0x00, 0x80, 0x01]), 4)).toEqual(new Uint8Array([0x00, 0x00, 0x80, 0x01]))
	})

	it("should leave a full width value unchanged", () => {
		expect(toFixedWidth(new Uint8Array([0x01, 0x02, 0x03, 0x04]), 4)).toEqual(new Uint8Array([0x01, 0x02, 0x03, 0x04]))
	})

	it("should throw on an empty value", () => {
		expect(() => toFixedWidth(new Uint8Array([]), 4)).toThrow("invalid ECDSA signature component")
	})

	it("should throw on a zero value", () => {
		expect(() => toFixedWidth(new Uint8Array([0x00, 0x00]), 4)).toThrow("invalid ECDSA signature component")
	})

	it("should throw on a value wider than the curve size", () => {
		expect(() => toFixedWidth(new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05]), 4)).toThrow("invalid ECDSA signature component")
	})
})

describe("ecdsaComponentSize", () => {
	it.each([
		["ecdsa-sha2-nistp256", 32],
		["sk-ecdsa-sha2-nistp256@openssh.com", 32],
		["ecdsa-sha2-nistp384", 48],
		["ecdsa-sha2-nistp521", 66],
	] as const)("%s should be %d bytes", (sig_algo, size) => {
		expect(ecdsaComponentSize(sig_algo)).toBe(size)
	})
})

describe("ECDSA signatures with short components", () => {
	for (const f of fixtures) {
		it(`${f.name} should parse to a fixed width r || s`, () => {
			expect(parse(f.signature).signature.raw_signature.byteLength).toBe(f.size * 2)
		})

		it(`${f.name} should verify`, async () => {
			expect(await verify(f.signature, f.data, { namespace: Namespace })).toBe(true)
		})

		it(`${f.name} should not verify against different data`, async () => {
			expect(await verify(f.signature, `${f.data}x`, { namespace: Namespace })).toBe(false)
		})
	}
})

describe("ECDSA proof of possession", () => {
	for (const curve of ["nistp256", "nistp384", "nistp521"] as const) {
		it(`should verify every ${curve} proof`, async () => {
			// the fixtures above cover short r and s deterministically, this
			// checks real ssh-keygen output end to end
			const key = generatePrivateKey("ecdsa", { curve })
			const failures: string[] = []
			for (let i = 0; i < 300; i++) {
				const proof = generateProof(key)
				if (!(await new ProofOfPossession(proof).verify())) {
					failures.push(proof)
				}
			}
			expect(failures).toEqual([])
		}, 120000)
	}
})
