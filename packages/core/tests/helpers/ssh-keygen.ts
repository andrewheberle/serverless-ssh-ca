import { spawnSync } from "node:child_process"
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import type { TestKey } from "../keys/types.js"

// ssh-keygen is the reference implementation that keys and certificates are
// checked against, so tests do not depend on another implementation of the
// OpenSSH formats

/**
 * Runs a function with a temporary directory that is removed afterwards
 */
export const withTempDir = <T>(fn: (dir: string) => T): T => {
	const dir = mkdtempSync(join(tmpdir(), "ssh-keygen-"))
	try {
		return fn(dir)
	} finally {
		rmSync(dir, { recursive: true, force: true })
	}
}

/**
 * Runs ssh-keygen, returning its exit status and output
 */
export const sshKeygen = (...args: string[]): { status: number | null, stdout: string, stderr: string } => {
	const result = spawnSync("ssh-keygen", args)

	return { status: result.status, stdout: result.stdout.toString(), stderr: result.stderr.toString() }
}

// runs ssh-keygen, throwing if it fails
const run = (...args: string[]): string => {
	const { status, stdout, stderr } = sshKeygen(...args)
	if (status !== 0) {
		throw new Error(`ssh-keygen ${args.join(" ")} failed: ${stderr}`)
	}

	return stdout
}

/**
 * Generates a key with ssh-keygen
 *
 * @param type The key type, as passed to ssh-keygen -t
 * @param bits The key size, as passed to ssh-keygen -b
 * @param options Other ssh-keygen options, for example ["-m", "PEM"]
 */
export const generateKey = (type: "ed25519" | "ecdsa" | "rsa", bits?: number, options: string[] = []): TestKey => {
	return withTempDir((dir) => {
		const file = join(dir, "key")
		run("-q", "-t", type, ...(bits === undefined ? [] : ["-b", `${bits}`]), "-N", "", "-C", "", ...options, "-f", file)

		return {
			privateKey: readFileSync(file, "utf8"),
			publicKey: readFileSync(`${file}.pub`, "utf8").trim(),
		}
	})
}

/**
 * Returns a test key for a private key, with its public key from ssh-keygen -y
 */
export const testKey = (privateKey: string): TestKey => {
	return withTempDir((dir) => {
		const file = join(dir, "key")
		writeFileSync(file, privateKey, { mode: 0o600 })

		return { privateKey, publicKey: run("-y", "-f", file).trim() }
	})
}

/**
 * Returns the SHA256 fingerprint of a public key as shown by ssh-keygen -l
 */
export const fingerprint = (publicKey: string): string => {
	return withTempDir((dir) => {
		const file = join(dir, "key.pub")
		writeFileSync(file, `${publicKey}\n`)

		// "<bits> <fingerprint> <comment> (<type>)"
		return run("-l", "-E", "sha256", "-f", file).split(" ")[1]!
	})
}

/**
 * A certificate as shown by ssh-keygen -L
 */
export type ListedCertificate = {
	/** The certificate type, for example "ssh-ed25519-cert-v01@openssh.com" */
	type: string
	kind: "user" | "host"
	/** The fingerprint of the certified public key */
	publicKey: string
	/** The fingerprint of the CA key that signed the certificate */
	signingCa: string
	/** The signature algorithm used by the CA, for example "ecdsa-sha2-nistp256" */
	signatureAlgorithm: string
	keyId: string
	serial: bigint
	validAfter: Date
	validBefore: Date
	principals: string[]
	criticalOptions: string[]
	extensions: string[]
}

// ssh-keygen prints times in the local time zone, to the second
const parseTime = (text: string): Date => {
	const [date, time] = text.split("T")
	const [year, month, day] = date!.split("-").map(Number)
	const [hours, minutes, seconds] = time!.split(":").map(Number)

	return new Date(year!, month! - 1, day!, hours!, minutes!, seconds!)
}

/**
 * Shows a certificate with ssh-keygen -L, which also verifies its signature
 *
 * @param certificate The certificate in OpenSSH format
 * @returns The fields of the certificate
 * @throws Error when ssh-keygen cannot parse the certificate or its signature does not verify
 */
export const listCertificate = (certificate: string): ListedCertificate => {
	const output = withTempDir((dir) => {
		const file = join(dir, "key-cert.pub")
		writeFileSync(file, `${certificate}\n`)

		return run("-L", "-f", file)
	})

	const value = (name: string): string => {
		const match = new RegExp(`^\\s+${name}: ?(.*)$`, "m").exec(output)
		if (match === null) {
			throw new Error(`ssh-keygen -L output did not include ${name}:\n${output}`)
		}

		return match[1]!
	}

	// a list is either "(none)" on the same line or one value per indented line
	const list = (name: string): string[] => {
		const match = new RegExp(`^(\\s+)${name}: ?(.*)\\n((?:\\1\\s+.*\\n?)*)`, "m").exec(output)
		if (match === null) {
			throw new Error(`ssh-keygen -L output did not include ${name}:\n${output}`)
		}
		if (match[2] === "(none)") {
			return []
		}

		return match[3]!.split("\n").map((line) => line.trim()).filter((line) => line !== "")
	}

	const [type, kind] = value("Type").split(" ")
	const signingCa = /^\S+ (\S+) \(using (\S+)\)$/.exec(value("Signing CA"))
	const valid = /^from (\S+) to (\S+)$/.exec(value("Valid"))
	if (signingCa === null || valid === null) {
		throw new Error(`unexpected ssh-keygen -L output:\n${output}`)
	}

	return {
		type: type!,
		kind: kind as "user" | "host",
		publicKey: value("Public key").split(" ")[1]!,
		signingCa: signingCa[1]!,
		signatureAlgorithm: signingCa[2]!,
		keyId: JSON.parse(value("Key ID")) as string,
		serial: BigInt(value("Serial")),
		validAfter: parseTime(valid[1]!),
		validBefore: parseTime(valid[2]!),
		principals: list("Principals"),
		criticalOptions: list("Critical Options"),
		extensions: list("Extensions"),
	}
}

/**
 * Signs a certificate with ssh-keygen -s
 *
 * @param ca The CA key to sign with
 * @param publicKey The public key to certify
 * @param options The fields of the certificate
 * @returns The certificate in OpenSSH format
 */
export const signCertificate = (ca: TestKey, publicKey: string, options: {
	kind: "user" | "host"
	keyId: string
	principals: string[]
	serial?: bigint
	/** A validity interval as passed to ssh-keygen -V, for example "-5m:+1h" */
	validity?: string
}): string => {
	return withTempDir((dir) => {
		const caFile = join(dir, "ca")
		writeFileSync(caFile, ca.privateKey, { mode: 0o600 })
		const keyFile = join(dir, "key.pub")
		writeFileSync(keyFile, `${publicKey}\n`)

		run("-q", "-s", caFile, "-I", options.keyId, "-n", options.principals.join(","),
			...(options.kind === "host" ? ["-h"] : []),
			...(options.serial === undefined ? [] : ["-z", `${options.serial}`]),
			...(options.validity === undefined ? [] : ["-V", options.validity]),
			keyFile)

		return readFileSync(join(dir, "key-cert.pub"), "utf8").trim()
	})
}

/**
 * Verifies an SSHSIG signature with ssh-keygen -Y verify
 *
 * @param publicKey The public key the signature must have been made with
 * @param namespace The namespace the signature must have been made for
 * @param data The data that was signed
 * @param signature The armored signature
 * @returns true if ssh-keygen verified the signature
 */
export const verifySignature = (publicKey: string, namespace: string, data: Uint8Array, signature: string): boolean => {
	return withTempDir((dir) => {
		const signers = join(dir, "allowed_signers")
		writeFileSync(signers, `signer ${publicKey}\n`)
		const signatureFile = join(dir, "data.sig")
		writeFileSync(signatureFile, signature)

		const result = spawnSync("ssh-keygen", ["-Y", "verify", "-f", signers, "-I", "signer", "-n", namespace, "-s", signatureFile], { input: data })

		return result.status === 0
	})
}

/**
 * A KRL as shown by ssh-keygen -Q -l
 */
export type ListedKrl = {
	version: bigint
	/** The fingerprint of the CA key the certificate sections are for */
	ca: string | undefined
	serials: bigint[]
	keyIds: string[]
}

/**
 * Shows a KRL with ssh-keygen -Q -l
 *
 * @throws Error when ssh-keygen cannot parse the KRL
 */
export const listKrl = (krl: Uint8Array): ListedKrl => {
	const output = withTempDir((dir) => {
		const file = join(dir, "krl")
		writeFileSync(file, krl)

		return run("-Q", "-l", "-f", file)
	})

	const lines = output.split("\n")
	const version = /^# KRL version (\d+)$/m.exec(output)
	if (version === null) {
		throw new Error(`unexpected ssh-keygen -Q -l output:\n${output}`)
	}

	return {
		version: BigInt(version[1]!),
		ca: /^# CA key \S+ (\S+)$/m.exec(output)?.[1],
		serials: lines.filter((l) => l.startsWith("serial: ")).map((l) => BigInt(l.slice("serial: ".length))),
		keyIds: lines.filter((l) => l.startsWith("id: ")).map((l) => l.slice("id: ".length)),
	}
}

/**
 * Returns whether ssh-keygen -Q reports a certificate as revoked by a KRL
 */
export const isRevoked = (krl: Uint8Array, certificate: string): boolean => {
	return withTempDir((dir) => {
		const krlFile = join(dir, "krl")
		writeFileSync(krlFile, krl)
		const certificateFile = join(dir, "key-cert.pub")
		writeFileSync(certificateFile, `${certificate}\n`)

		const { status, stdout, stderr } = sshKeygen("-Q", "-f", krlFile, certificateFile)
		if (stdout.includes(": REVOKED")) {
			return true
		}
		if (status === 0 && stdout.includes(": ok")) {
			return false
		}

		throw new Error(`unexpected ssh-keygen -Q output: ${stdout}${stderr}`)
	})
}
