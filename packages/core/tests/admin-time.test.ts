// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it } from "vitest"
import { CertificateType } from "../src/db/types.js"
import type { CertificateDetails, CertificateStatus } from "../src/db/index.js"
import { CertificateDetailPage, CertificateListPage } from "../src/admin/pages.js"
import { TimeScript, TimeZoneStorageKey } from "../src/admin/time.js"

// the times the script is run against, in the browser's time zone set by
// TZ, as Node applies a change to TZ straight away
let savedTz: string | undefined

beforeEach(() => {
	savedTz = process.env.TZ
	window.localStorage.clear()
})

afterEach(() => {
	if (savedTz === undefined) {
		delete process.env.TZ
	} else {
		process.env.TZ = savedTz
	}
	window.localStorage.clear()
})

const certificate = (overrides: Partial<CertificateDetails> = {}): CertificateDetails => ({
	id: 1,
	serial: "1234",
	key_id: "alice@example.com",
	principals: "UID=alice",
	extensions: "permit-pty",
	valid_after: new Date("2026-11-04T21:10:54.000Z"),
	valid_before: new Date("2026-11-05T09:10:54.000Z"),
	revoked_at: null,
	certificate_type: CertificateType.User,
	public_key: null,
	requested_by: "alice@example.com",
	renewal_of: null,
	revoked_by: null,
	revocation_reason: null,
	request_address: null,
	revocation_address: null,
	...overrides,
})

// replaces the document's body with what a rendered page shows. It is parsed
// in a template, which is inert, and its head is dropped: that only links
// the stylesheet and script, which happy-dom would try to load
const load = async (page: unknown): Promise<void> => {
	const template = document.createElement("template")
	template.innerHTML = String(await page)
	for (const element of Array.from(template.content.querySelectorAll("meta, title, link, script"))) {
		element.remove()
	}

	document.body.replaceChildren(template.content)
}

const detailPage = async (overrides: Partial<CertificateDetails> = {}, status: CertificateStatus = "valid"): Promise<void> => {
	await load(CertificateDetailPage({
		email: "admin@example.com",
		kind: "user",
		certificate: certificate(overrides),
		status,
		renewal: { renewalOf: undefined, renewedAs: undefined },
	}))
}

const listPage = async (certificates: CertificateDetails[] = [certificate()]): Promise<void> => {
	await load(CertificateListPage({
		email: "admin@example.com",
		kind: "user",
		query: { status: "valid" },
		certificates: certificates.map((c) => ({ ...c, status: "valid" })),
		nextPage: undefined,
	}))
}

// runs the script exactly as it is served, against the current document
const runScript = (): void => {
	new Function(TimeScript)()
}

const times = (): { text: string | null, title: string }[] =>
	Array.from(document.querySelectorAll("time")).map((t) => ({ text: t.textContent, title: t.title }))

const switchElement = (): HTMLElement => {
	const element = document.getElementById("time-zone")
	if (element === null) {
		throw new Error("no time zone switch")
	}

	return element
}

const button = (mode: "local" | "utc"): HTMLButtonElement => {
	const element = document.querySelector<HTMLButtonElement>(`#time-zone button[data-time-zone="${mode}"]`)
	if (element === null) {
		throw new Error(`no ${mode} button`)
	}

	return element
}

describe("admin UI times", () => {
	it("should show times in the browser's time zone by default, with the offset, to the precision of each page", async () => {
		process.env.TZ = "Australia/Perth"

		await listPage()
		runScript()
		expect(times()).toEqual([
			{ text: "2026-11-05 05:10 UTC+8", title: "2026-11-04 21:10 UTC" },
			{ text: "2026-11-05 17:10 UTC+8", title: "2026-11-05 09:10 UTC" },
		])

		await detailPage()
		runScript()
		expect(times()).toEqual([
			{ text: "2026-11-05 05:10:54 UTC+8", title: "2026-11-04 21:10:54 UTC" },
			{ text: "2026-11-05 17:10:54 UTC+8", title: "2026-11-05 09:10:54 UTC" },
		])
	})

	it.each([
		["Asia/Kolkata", "2026-11-05 02:40 UTC+5:30"],
		["America/St_Johns", "2026-11-04 17:40 UTC-3:30"],
		["Europe/London", "2026-11-04 21:10 UTC+0"],
		["Pacific/Kiritimati", "2026-11-05 11:10 UTC+14"],
	])("should show the offset of %s", async (zone, text) => {
		process.env.TZ = zone

		await listPage()
		runScript()
		expect(times()[0]?.text).toBe(text)
	})

	it("should show the offset of each time, which changes with daylight saving", async () => {
		process.env.TZ = "Australia/Sydney"

		await detailPage({
			valid_after: new Date("2026-03-28T22:00:00.000Z"),
			valid_before: new Date("2026-04-11T23:00:00.000Z"),
		})
		runScript()
		expect(times().map((t) => t.text)).toEqual(["2026-03-29 09:00:00 UTC+11", "2026-04-12 09:00:00 UTC+10"])
	})

	it("should show the revocation time too", async () => {
		process.env.TZ = "Australia/Perth"

		await detailPage({ revoked_at: new Date("2026-11-05T01:02:03.000Z"), revoked_by: "admin@example.com", revocation_reason: "lost" }, "revoked")
		runScript()
		expect(times()[2]).toEqual({ text: "2026-11-05 09:02:03 UTC+8", title: "2026-11-05 01:02:03 UTC" })
	})

	it("should reveal the switch, with local time pressed and the browser's time zone on the local button", async () => {
		process.env.TZ = "Australia/Perth"

		await listPage()
		expect(switchElement().hidden).toBe(true)
		runScript()

		expect(switchElement().hidden).toBe(false)
		expect(button("local").getAttribute("aria-pressed")).toBe("true")
		expect(button("utc").getAttribute("aria-pressed")).toBe("false")
		expect(button("local").title).toBe("Australia/Perth")
	})

	it("should switch to UTC, with the local time and time zone on hover, and remember it", async () => {
		process.env.TZ = "Australia/Perth"

		await listPage()
		runScript()
		button("utc").click()

		expect(times()[0]).toEqual({ text: "2026-11-04 21:10 UTC", title: "2026-11-05 05:10 UTC+8 (Australia/Perth)" })
		expect(button("local").getAttribute("aria-pressed")).toBe("false")
		expect(button("utc").getAttribute("aria-pressed")).toBe("true")
		expect(window.localStorage.getItem(TimeZoneStorageKey)).toBe("utc")

		// the next page is shown in UTC
		await detailPage()
		runScript()
		expect(times()[0]?.text).toBe("2026-11-04 21:10:54 UTC")
		expect(button("utc").getAttribute("aria-pressed")).toBe("true")
	})

	it("should switch back to local time, and remember it", async () => {
		process.env.TZ = "Australia/Perth"
		window.localStorage.setItem(TimeZoneStorageKey, "utc")

		await listPage()
		runScript()
		button("local").click()

		expect(times()[0]?.text).toBe("2026-11-05 05:10 UTC+8")
		expect(window.localStorage.getItem(TimeZoneStorageKey)).toBe("local")
	})

	it("should show local time for a stored value it does not know", async () => {
		process.env.TZ = "Australia/Perth"
		window.localStorage.setItem(TimeZoneStorageKey, "nonsense")

		await listPage()
		runScript()
		expect(times()[0]?.text).toBe("2026-11-05 05:10 UTC+8")
	})

	describe("with storage blocked", () => {
		let saved: PropertyDescriptor | undefined

		beforeEach(() => {
			saved = Object.getOwnPropertyDescriptor(window, "localStorage")
			Object.defineProperty(window, "localStorage", {
				configurable: true,
				get: () => {
					throw new DOMException("storage is blocked", "SecurityError")
				},
			})
		})

		afterEach(() => {
			if (saved === undefined) {
				Reflect.deleteProperty(window, "localStorage")
			} else {
				Object.defineProperty(window, "localStorage", saved)
			}
		})

		it("should show local time, and still switch on the page", async () => {
			process.env.TZ = "Australia/Perth"

			await listPage()
			runScript()
			expect(times()[0]?.text).toBe("2026-11-05 05:10 UTC+8")

			button("utc").click()
			expect(times()[0]?.text).toBe("2026-11-04 21:10 UTC")
		})
	})

	it("should leave a time without a precision as the server rendered it", async () => {
		process.env.TZ = "Australia/Perth"

		await listPage()
		document.body.insertAdjacentHTML("beforeend", `<time datetime="2026-11-04T21:10:54.000Z">as rendered</time>`)
		runScript()
		expect(times().at(-1)?.text).toBe("as rendered")
	})
})
