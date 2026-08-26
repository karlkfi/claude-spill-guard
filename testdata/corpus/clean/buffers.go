package transport

// Sizes are powers of two so a read never straddles two pages on the
// platforms we ship. The comment is here because 65536 has been "tuned" three
// times and every tuning put it back.
const (
	readBuffer  = 65536
	writeBuffer = 65536
	headerLimit = 16384
	frameLimit  = 1048576
	backlog     = 4096
)

// Port range the local test harness allocates from. Kept out of the ephemeral
// range so a flaky test cannot collide with a real dial.
const (
	testPortLow  = 30000
	testPortHigh = 30999
)

var defaultBind = "127.0.0.1:30443"
