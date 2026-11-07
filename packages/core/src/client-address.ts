import { z } from "zod"

/**
 * Returns the client address of a request, the IP address it came from as
 * reported by a proxy the CA is configured to trust, or undefined if it is not
 * known. See {@link SshCaOptions.clientAddress}.
 */
export type ClientAddressSource = (req: Request) => string | undefined

// a client address must be an IP address, as it is recorded in the audit trail
const ClientAddressSchema = z.union([z.ipv4(), z.ipv6()])

/** A client address that has been checked to be an IPv4 or IPv6 address */
export type ClientAddress = z.infer<typeof ClientAddressSchema>

/**
 * The client address of a request as it is recorded.
 *
 * - `known`: the source gave an IP address
 * - `none`: there is no source, or it gave no address
 * - `invalid`: the source gave a value that is not an IP address, which is not recorded
 */
export type ClientAddressResult =
	| { kind: "known", address: ClientAddress }
	| { kind: "none" }
	| { kind: "invalid", value: string }

/**
 * Returns the client address of a request from a source, checking that it is
 * an IPv4 or IPv6 address.
 *
 * @param source Where the client address is read from, or undefined if it is not recorded
 * @param req The request
 * @returns The client address, see {@link ClientAddressResult}
 */
export const clientAddressOf = (source: ClientAddressSource | undefined, req: Request): ClientAddressResult => {
	const value = source?.(req)
	if (value === undefined || value === "") {
		return { kind: "none" }
	}

	const address = ClientAddressSchema.safeParse(value)
	return address.success ? { kind: "known", address: address.data } : { kind: "invalid", value }
}
