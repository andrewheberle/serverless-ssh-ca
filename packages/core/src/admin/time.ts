import { hashedAsset, type HashedAsset } from "../web/assets.js"

/**
 * The key in `localStorage` that remembers whether an admin chose to see
 * times in their browser's time zone (`local`) or in UTC (`utc`). Nothing is
 * stored until they choose, and times are shown in local time until then.
 */
export const TimeZoneStorageKey = "admin-time-zone"

/**
 * The admin UI's only script, which shows times in the browser's time zone,
 * see ADR-0004. It only changes how times are displayed: pages are rendered
 * by the server with times in UTC, and work fully without it.
 *
 * It rewrites the text of every `<time>` with a `datetime` and a
 * `data-precision` of `minute` or `second`, either in local time with the
 * UTC offset of that moment (such as `2026-11-05 05:10 UTC+8`) or in UTC
 * (such as `2026-11-04 21:10 UTC`), and puts the other one in its `title`.
 * It reveals the hidden `#time-zone` switch, whose buttons have a
 * `data-time-zone` of `local` or `utc` and an `aria-pressed` it keeps up to
 * date, and remembers the choice made with it under
 * {@link TimeZoneStorageKey}.
 *
 * It is plain JavaScript rather than a compiled function, so what is served
 * is exactly what is tested, whatever the bundler of the worker does to
 * functions.
 */
export const TimeScript = `"use strict";
(function () {
	var storageKey = ${JSON.stringify(TimeZoneStorageKey)};

	function pad(n) {
		return String(n).padStart(2, "0");
	}

	// the browser's time zone, such as Australia/Perth, if it says
	var zone = (function () {
		try {
			return Intl.DateTimeFormat().resolvedOptions().timeZone || "";
		} catch (e) {
			return "";
		}
	})();

	// the offset from UTC of a moment in the browser's time zone, such as
	// UTC+8, UTC+5:30, UTC-3:30 or UTC+0
	function offset(date) {
		var minutes = -date.getTimezoneOffset();
		var sign = minutes < 0 ? "-" : "+";
		var abs = Math.abs(minutes);
		var hours = Math.floor(abs / 60);
		var rest = abs % 60;
		return "UTC" + sign + hours + (rest === 0 ? "" : ":" + pad(rest));
	}

	function local(date, precision) {
		return date.getFullYear() + "-" + pad(date.getMonth() + 1) + "-" + pad(date.getDate()) + " " +
			pad(date.getHours()) + ":" + pad(date.getMinutes()) +
			(precision === "second" ? ":" + pad(date.getSeconds()) : "") +
			" " + offset(date);
	}

	function utc(date, precision) {
		var iso = date.toISOString();
		return iso.slice(0, 10) + " " + iso.slice(11, precision === "second" ? 19 : 16) + " UTC";
	}

	function read() {
		try {
			return window.localStorage.getItem(storageKey) === "utc" ? "utc" : "local";
		} catch (e) {
			return "local";
		}
	}

	function save(mode) {
		try {
			window.localStorage.setItem(storageKey, mode);
		} catch (e) {
			// the choice still applies to this page, it is just not remembered
		}
	}

	function show(mode) {
		var times = document.querySelectorAll("time[datetime][data-precision]");
		for (var i = 0; i < times.length; i++) {
			var time = times[i];
			var date = new Date(time.getAttribute("datetime"));
			if (isNaN(date.getTime())) {
				continue;
			}

			var precision = time.getAttribute("data-precision") === "second" ? "second" : "minute";
			var other = local(date, precision) + (zone === "" ? "" : " (" + zone + ")");
			time.textContent = mode === "local" ? local(date, precision) : utc(date, precision);
			time.title = mode === "local" ? utc(date, precision) : other;
		}

		var buttons = document.querySelectorAll("#time-zone button[data-time-zone]");
		for (var j = 0; j < buttons.length; j++) {
			buttons[j].setAttribute("aria-pressed", buttons[j].getAttribute("data-time-zone") === mode ? "true" : "false");
		}
	}

	function start() {
		show(read());

		var toggle = document.getElementById("time-zone");
		if (toggle === null) {
			return;
		}

		var buttons = toggle.querySelectorAll("button[data-time-zone]");
		for (var i = 0; i < buttons.length; i++) {
			(function (button) {
				var mode = button.getAttribute("data-time-zone") === "utc" ? "utc" : "local";
				if (mode === "local" && zone !== "") {
					button.title = zone;
				}
				button.addEventListener("click", function () {
					save(mode);
					show(mode);
				});
			})(buttons[i]);
		}
		toggle.hidden = false;
	}

	if (document.readyState === "loading") {
		document.addEventListener("DOMContentLoaded", start);
	} else {
		start();
	}
})();
`

/** The admin UI's script, served under a name with a hash of {@link TimeScript} */
export const TimeScriptAsset: HashedAsset = hashedAsset("/admin", "time", "js", TimeScript)

/** The path the admin UI's script is served at, such as `/admin/time-1a2b3c4d.js` */
export const TimeScriptPath = TimeScriptAsset.path
