import { IttyRouter, IRequest, error, IRequestStrict } from "itty-router"
import { router as apiv1 } from "./api/v1"


export type CFArgs = [Env, ExecutionContext]

export const router = IttyRouter<IRequest, CFArgs>()

router
    .all("/api/v1/*", apiv1.fetch)
    .all("*", () => error(404))

