import { IttyRouter, IRequest, error } from "itty-router"
import { router as apiv1 } from "./api/v1"
import { router as deviceUI } from "./device-ui"

export type CFArgs = [Env, ExecutionContext]

export const router = IttyRouter<IRequest, CFArgs>()

router
    .all("/api/v1/*", apiv1.fetch)
    .all("/device/*", deviceUI.fetch)
    .all("*", () => error(404))
