const fs = require("fs")
const { createApp } = require("../src/router")
const { makeEnv } = require("../tests/env")

const env = makeEnv()
const openapi = createApp(env)
const schema = openapi.schema

fs.writeFileSync('./openapi.json', JSON.stringify(schema, null, 2))
