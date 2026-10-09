/**
 * A running test server, returned by {@link startTestServer}.
 */
export type TestServer = {
	/** The port the CA is listening on at 127.0.0.1 */
	port: number
	/** Stop the CA and release its resources */
	close(): Promise<void>
}
