import { json } from "itty-router"
import { router } from "./router"

export default {
	async fetch(request, env, ctx): Promise<Response> {
		return await router.fetch(request, env, ctx).then(json);
	},
} satisfies ExportedHandler<Env>;
