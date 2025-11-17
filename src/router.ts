import { IttyRouter, IRequest, error } from "itty-router"
import { router as apiv1 } from "./api/v1"
import { router as apiv2 } from "./api/v2"
import { router as currentApi } from "./api/current"

export type CFArgs = [Env, ExecutionContext]

export const router = IttyRouter<IRequest, CFArgs>()

router
    .all("/api/v1/*", apiv1.fetch)
    .all("/api/v2/*", apiv2.fetch)
    .all("/api/*", currentApi.fetch)
    .all("*", () => error(404))
