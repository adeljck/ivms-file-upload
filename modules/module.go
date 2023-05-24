package modules

type Ivms struct {
	target     string
	targetFile string
	targets    []string
	upload     bool
	check      bool
	vuln       bool
	shellPath  string
	shellFile  string
}
