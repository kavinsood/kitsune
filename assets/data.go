package assets

import _ "embed"

//go:embed fingerprints_data.json
var FingerprintsJSON string

//go:embed categories_data.json
var CategoriesJSON string