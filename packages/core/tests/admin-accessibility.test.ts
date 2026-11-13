import { describe, expect, it } from "vitest"
import { Stylesheet } from "../src/admin/pages.js"
import { BaseStylesheet } from "../src/web/styles.js"

type Rgb = [number, number, number]

// converts an OKLCH colour to linear sRGB, clipped to the sRGB gamut
const oklchToLinearRgb = (l: number, c: number, h: number): Rgb => {
	const a = c * Math.cos(h * Math.PI / 180)
	const b = c * Math.sin(h * Math.PI / 180)
	const l_ = (l + 0.3963377774 * a + 0.2158037573 * b) ** 3
	const m_ = (l - 0.1055613458 * a - 0.0638541728 * b) ** 3
	const s_ = (l - 0.0894841775 * a - 1.2914855480 * b) ** 3
	const clip = (v: number): number => Math.min(Math.max(v, 0), 1)
	return [
		clip(4.0767416621 * l_ - 3.3077115913 * m_ + 0.2309699292 * s_),
		clip(-1.2684380046 * l_ + 2.6097574011 * m_ - 0.3413193965 * s_),
		clip(-0.0041960863 * l_ - 0.7034186147 * m_ + 1.7076147010 * s_),
	]
}

// parses a colour as the stylesheet writes it: #fff or an opaque oklch()
const parse = (colour: string): Rgb => {
	if (colour === "#fff") {
		return [1, 1, 1]
	}
	const match = /^oklch\(([\d.]+)(%?) ([\d.]+) ([\d.]+)\)$/.exec(colour)
	if (match === null) {
		throw new Error(`not an opaque colour: ${colour}`)
	}
	const lightness = Number(match[1]) / (match[2] === "%" ? 100 : 1)
	return oklchToLinearRgb(lightness, Number(match[3]), Number(match[4]))
}

// the light and dark values of a custom property of the base stylesheet
const token = (name: string): { light: string, dark: string } => {
	const match = new RegExp(`--${name}: light-dark\\((#fff|oklch\\([^)]*\\)), (#fff|oklch\\([^)]*\\))\\);`).exec(BaseStylesheet)
	if (match?.[1] === undefined || match[2] === undefined) {
		throw new Error(`no light-dark value for --${name}`)
	}
	return { light: match[1], dark: match[2] }
}

// the WCAG contrast ratio of two colours
const contrast = (a: Rgb, b: Rgb): number => {
	const luminance = ([r, g, b]: Rgb): number => 0.2126 * r + 0.7152 * g + 0.0722 * b
	const [high, low] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number]
	return (high + 0.05) / (low + 0.05)
}

describe("admin UI colour contrast (#591)", () => {
	it.each(["light", "dark"] as const)("should give white text on a danger button at least 4.5:1 in %s mode", (mode) => {
		expect(contrast([1, 1, 1], parse(token("danger-strong")[mode]))).toBeGreaterThanOrEqual(4.5)
	})

	it.each(["light", "dark"] as const)("should give tabs that are not selected at least 4.5:1 in %s mode", (mode) => {
		expect(contrast(parse(token("text-muted")[mode]), parse(token("recessed")[mode]))).toBeGreaterThanOrEqual(4.5)
	})

	it.each(["light", "dark"] as const)("should give the boundary of a form control at least 3:1 against it and the page in %s mode", (mode) => {
		const line = parse(token("control-line")[mode])
		for (const background of ["control", "base", "canvas"]) {
			expect(contrast(line, parse(token(background)[mode]))).toBeGreaterThanOrEqual(3)
		}
	})
})

describe("admin UI stylesheet (#591)", () => {
	it("should show keyboard focus on a checkbox, even an invalid one", () => {
		expect(Stylesheet).toMatch(/input\[type="checkbox"\]:focus-visible \{\s*outline: 2px solid var\(--brand\);/)
		// the rules have the same specificity, so the focus rule must come last
		expect(Stylesheet.indexOf("input[type=\"checkbox\"]:focus-visible")).toBeGreaterThan(Stylesheet.indexOf("input[type=\"checkbox\"][aria-invalid=\"true\"]"))
	})

	it("should use the strong danger colour for danger buttons", () => {
		expect(Stylesheet).toMatch(/\.button\.danger \{\s*background: var\(--danger-strong\);/)
	})

	it("should outline form controls with the control boundary colour", () => {
		expect(Stylesheet).toMatch(/input, select \{[^}]*box-shadow: 0 0 0 1px var\(--control-line\);/)
		expect(Stylesheet).toMatch(/textarea \{[^}]*box-shadow: 0 0 0 1px var\(--control-line\);/)
	})

	it("should keep serials in tables on one line", () => {
		expect(Stylesheet).toMatch(/td\.mono \{\s*white-space: nowrap;/)
	})
})
