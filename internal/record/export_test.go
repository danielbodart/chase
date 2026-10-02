package record

// Endpoint is an endpoint entry, as a test makes one.
func Endpoint(method, path string) any { return endpoint{Methods: []string{method}, Path: path} }

// Save is save, for a test that keeps recordings of its own.
var Save = save
