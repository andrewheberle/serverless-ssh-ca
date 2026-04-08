import fs from 'fs'
import { openapi } from '../src/router'

const schema = openapi.schema

fs.writeFileSync('./openapi.json', JSON.stringify(schema, null, 2))
