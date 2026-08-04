package globals

// DevMode loads .env from disk and skips the Authorization middleware in
// main.go. It defaults to false because a deployment built from a clean
// checkout would otherwise serve every route without a token. Set it to true
// while developing locally.
var (
	DevMode bool = false
)
