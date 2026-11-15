import { type ApiException, formatChanfanaError, InternalServerErrorException } from "chanfana"

/**
 * Returns the response for `err`, formatted by chanfana as it formats the
 * errors thrown by the API's routes, so every error response has the same
 * shape.
 */
export const errorResponse = (err: ApiException): Response => {
    const response = formatChanfanaError(err)
    if (response === null) {
        // chanfana formats every ApiException, so this is only reached if it
        // stops doing so, which must not be answered with a success
        throw new Error("chanfana did not format an API exception", { cause: err })
    }

    return response
}

/**
 * Returns the response to a request that failed for a reason the client is
 * not told, which is the same 500 the API's routes answer with.
 */
export const internalServerErrorResponse = (): Response => errorResponse(new InternalServerErrorException())
