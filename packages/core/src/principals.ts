/** The kind of certificate a principal is for */
export type PrincipalKind = "user" | "host"

// characters that OpenSSH treats as pattern syntax when matching principals,
// or that separate the entries of a list of principals, such as the
// principals="..." option of authorized_keys
const PatternChars = /[*?!,]/
// whitespace and control characters, which no user or host name contains
const InvalidChars = /[\s\p{Cc}]/u

/**
 * Returns why a principal cannot be included on a certificate, or undefined
 * if it can be.
 *
 * OpenSSH matches the principals of a host certificate as patterns, so a
 * principal such as `*` would make the certificate valid for every host that
 * trusts the CA, and a server that restricts a user certificate with a list
 * of principals may read a principal containing a comma as several. Principals
 * are otherwise not restricted, as hosts may be reached by IP address, bare
 * host name or fully qualified domain name, and users may have any name.
 *
 * @param kind The kind of certificate the principal is for, which is named in the reason
 * @param principal The principal to check
 * @returns The reason the principal cannot be used, or undefined if it can be
 */
export const principalIssue = (kind: PrincipalKind, principal: string): string | undefined => {
	if (principal === "") {
		return `${kind} certificate principals must not be empty`
	}

	if (PatternChars.test(principal)) {
		return `${kind} certificate principal ${JSON.stringify(principal)} must not contain wildcard or pattern characters (*, ?, ! or ,)`
	}

	if (InvalidChars.test(principal)) {
		return `${kind} certificate principal ${JSON.stringify(principal)} must not contain whitespace or control characters`
	}

	return undefined
}
