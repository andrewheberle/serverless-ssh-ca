import { describe, it, expect } from "vitest"
import { authenticate, type AuthenticationResult, type RequesterConfig } from "../src/requester.js"
import { CertificateType } from "../src/db/types.js"
import { logger } from "../src/logger.js"
import { makeEnv } from "./env.js"
import { getAccessToken, getIdentityToken, getOpaqueAccessToken } from "./helpers/token.js"

const port = parseInt(process.env.OIDC_PORT ?? "4567")
const email = "user@example.com"
const sub = "user123"
const l = logger(makeEnv())

const config = (overrides: Partial<RequesterConfig> = {}): RequesterConfig => makeEnv(overrides)

// tokens are requested with arbitrary claims, so the test IdP is given them as is
type Claims = Record<string, unknown>
const accessToken = async (claims: Claims): Promise<string> => await getAccessToken(claims as { sub: string, email: string })
const identityToken = async (claims: Claims): Promise<string> => await getIdentityToken(claims as { sub: string, email: string })

const run = async (
	tokens: { access?: Claims | string, identity?: Claims | string } = {},
	options: { config?: RequesterConfig, certificateType?: CertificateType } = {},
): Promise<AuthenticationResult> => {
	const access = tokens.access ?? { sub, email }
	const identity = tokens.identity ?? { sub, email }

	return await authenticate(
		options.config ?? config(),
		{
			authorization: typeof access === "string" ? access : await accessToken(access),
			identityToken: typeof identity === "string" ? identity : await identityToken(identity),
		},
		options.certificateType ?? CertificateType.User,
		l,
	)
}

const invalid = (...issues: { token: "access" | "identity", message: string }[]): AuthenticationResult => ({ kind: "invalid", issues })

describe("authenticate", () => {
	it("should establish the requester from both tokens", async () => {
		expect(await run({ identity: { sub, email, groups: ["admins", "ops team"] } })).toEqual({
			kind: "authenticated",
			requester: { email, sub, principals: ["admins", "ops_team"] },
		})
	})

	it("should report both tokens when neither is accepted", async () => {
		expect(await run({ access: "Bearer foo", identity: "foo" })).toEqual(invalid(
			{ token: "access", message: "the access token was invalid" },
			{ token: "identity", message: "problem parsing identity token" },
		))
	})

	describe("access token", () => {
		it.each([
			["is empty", ""],
			["is not a Bearer token", "Basic foo"],
			["is only the Bearer prefix", "Bearer "],
		])("should not be accepted when the Authorization header %s", async (_case, authorization) => {
			expect(await run({ access: authorization })).toEqual(invalid({ token: "access", message: "authorization header must be a Bearer token" }))
		})

		it("should not be accepted when it is not a JWT", async () => {
			expect(await run({ access: "Bearer foo" })).toEqual(invalid({ token: "access", message: "the access token was invalid" }))
		})

		it("should not be accepted when it has expired", async () => {
			const result = await run({ access: { sub, email, exp: Math.floor(Date.now() / 1000) - 3600 } })
			expect(result).toEqual(invalid({ token: "access", message: "the access token has expired" }))
		})

		it("should not be accepted when its signature is not valid", async () => {
			const token = await accessToken({ sub, email })
			const other = await accessToken({ sub: "user456", email: "other@example.com" })

			// keep the signature but replace the payload with another token's
			const [header, , signature] = token.split(".")
			const [, payload] = other.split(".")

			expect(await run({ access: `${header}.${payload}.${signature}` })).toEqual(invalid({ token: "access", message: "the access token signature verification failed" }))
		})

		it("should not be accepted when it is from another issuer", async () => {
			const result = await run({ access: { sub, email, iss: "https://idp.example.com" } })
			expect(result).toEqual(invalid({ token: "access", message: "claim validation of the JWT failed" }))
		})

		it("should not be accepted when it is for another audience", async () => {
			const result = await run({ access: { sub, email, aud: "another" } })
			expect(result).toEqual(invalid({ token: "access", message: "claim validation of the JWT failed" }))
		})

		it("should be checked against JWT_ACCESS_TOKEN_AUD when it is set", async () => {
			const options = { config: config({ JWT_ACCESS_TOKEN_AUD: "api" }) }
			expect(await run({ access: { sub, email, aud: "api" } }, options)).toMatchObject({ kind: "authenticated" })
			expect(await run({}, options)).toEqual(invalid({ token: "access", message: "claim validation of the JWT failed" }))
		})

		it.each([
			["is missing", {}, "JWT was verified but was missing required email claim"],
			["is empty", { email: "" }, "JWT was verified but the email or email_verified claim was not valid"],
			["is not an email address", { email: "root" }, "JWT was verified but the email or email_verified claim was not valid"],
			["is a number", { email: 42 }, "JWT was verified but the email or email_verified claim was not valid"],
			["is a list", { email: ["a@example.com", "b@example.com"] }, "JWT was verified but the email or email_verified claim was not valid"],
			["is not verified", { email, email_verified: false }, "JWT was verified but the email address has not been verified by the IdP"],
			["has an email_verified that is not a boolean", { email, email_verified: "true" }, "JWT was verified but the email or email_verified claim was not valid"],
		])("should not be accepted when the email %s", async (_case, claims, message) => {
			expect(await run({ access: { sub, ...claims } })).toEqual(invalid({ token: "access", message }))
		})

		it("should be accepted when the email has been verified", async () => {
			expect(await run({ access: { sub, email, email_verified: true } })).toMatchObject({ kind: "authenticated" })
		})

		it.each([
			["missing", undefined],
			["empty", ""],
			["a number", 123],
			["a list", [sub]],
		])("should not be accepted when the subject is %s", async (_case, value) => {
			const result = await run({ access: { sub: value, email } })
			expect(result).toEqual(invalid({ token: "access", message: "JWT was verified but was missing required sub claim" }))
		})
	})

	describe("access token verified with the userinfo endpoint", () => {
		const userinfo = { config: config({ OIDC_USERINFO_URL: `http://localhost:${port}/userinfo` }) }

		it("should be accepted when the userinfo endpoint accepts it", async () => {
			const access = await getOpaqueAccessToken({ claims: { sub, email } })
			expect(await run({ access }, userinfo)).toMatchObject({ kind: "authenticated", requester: { email, sub } })
		})

		it("should not be accepted when the userinfo endpoint does not accept it", async () => {
			expect(await run({ access: "Bearer unknown" }, userinfo)).toEqual(invalid({ token: "access", message: "the access token was not accepted by the userinfo endpoint" }))
		})

		it("should not be accepted when the userinfo claims cannot be used", async () => {
			const access = await getOpaqueAccessToken({ claims: { sub } })
			expect(await run({ access }, userinfo)).toEqual(invalid({ token: "access", message: "the userinfo response was missing required email claim" }))
		})

		it("should report the IdP as unavailable when the userinfo endpoint cannot be reached", async () => {
			const result = await run({}, { config: config({ OIDC_USERINFO_URL: "http://localhost:1/userinfo" }) })
			expect(result).toEqual({ kind: "unavailable", message: "the access token could not be verified with the userinfo endpoint" })
		})
	})

	describe("identity token", () => {
		it("should not be accepted when it is not a JWT", async () => {
			expect(await run({ identity: "foo" })).toEqual(invalid({ token: "identity", message: "problem parsing identity token" }))
		})

		it("should not be accepted when it is for another audience", async () => {
			const options = { config: config({ JWT_ACCESS_TOKEN_AUD: "api" }) }
			const result = await run({ access: { sub, email, aud: "api" }, identity: { sub, email, aud: "api" } }, options)
			expect(result).toEqual(invalid({ token: "identity", message: "problem parsing identity token" }))
		})

		it.each([
			["missing", undefined],
			["empty", ""],
			["a number", 123],
			["a list", [sub]],
		])("should not be accepted when the subject is %s", async (_case, value) => {
			const result = await run({ identity: { sub: value, email } })
			expect(result).toEqual(invalid({ token: "identity", message: "JWT was verified but was missing required sub claim" }))
		})

		it.each([
			["a number", 42],
			["an object", { foo: "bar" }],
			["an array of numbers", [1, 2]],
		])("should not be accepted when the principals claim is %s", async (_case, groups) => {
			const result = await run({ identity: { sub, email, groups } })
			expect(result).toEqual(invalid({ token: "identity", message: "the groups claim must be a string or an array of strings" }))
		})

		it.each([
			["missing", undefined, []],
			["null", null, []],
			["an empty string", "", []],
			["an empty list", [], []],
			["a string", "foo", ["foo"]],
			["a list", ["foo", "bar"], ["foo", "bar"]],
		])("should give the principals when the principals claim is %s", async (_case, groups, principals) => {
			const result = await run({ identity: { sub, email, groups } })
			expect(result).toEqual({ kind: "authenticated", requester: { email, sub, principals } })
		})
	})

	it("should not accept tokens for different subjects", async () => {
		expect(await run({ identity: { sub: "user456", email } })).toEqual({
			kind: "subjectMismatch",
			access: { email, sub },
			identity: { sub: "user456" },
		})
	})

	it("should report the CA as misconfigured when no audience is configured", async () => {
		expect(await run({}, { config: config({ JWT_AUD: "" }) })).toEqual({
			kind: "misconfigured",
			message: "no audience is configured for verifying tokens, set JWT_AUD",
		})
	})

	describe("host certificates", () => {
		const host = (overrides: Partial<RequesterConfig>) => ({ config: config(overrides), certificateType: CertificateType.Host })

		it("should be permitted for an allowed email address", async () => {
			expect(await run({}, host({ SSH_HOST_CERTIFICATE_ALLOWED_EMAILS: `admin@example.com,${email}` }))).toMatchObject({ kind: "authenticated" })
		})

		it("should be permitted for an allowed role", async () => {
			const result = await run({ identity: { sub, email, groups: ["ops"] } }, host({ SSH_HOST_CERTIFICATE_ALLOWED_ROLES: "admins,ops" }))
			expect(result).toMatchObject({ kind: "authenticated" })
		})

		it("should not be permitted otherwise", async () => {
			const result = await run({ identity: { sub, email, groups: ["users"] } }, host({ SSH_HOST_CERTIFICATE_ALLOWED_EMAILS: "admin@example.com", SSH_HOST_CERTIFICATE_ALLOWED_ROLES: "admins" }))
			expect(result).toEqual({ kind: "notPermitted", requester: { email, sub, principals: ["users"] } })
		})

		it("should not be permitted when nothing is allowed", async () => {
			expect(await run({}, host({}))).toMatchObject({ kind: "notPermitted" })
		})

		it("should be checked only after the tokens are for the same subject", async () => {
			expect(await run({ identity: { sub: "user456", email } }, host({}))).toMatchObject({ kind: "subjectMismatch" })
		})
	})
})
